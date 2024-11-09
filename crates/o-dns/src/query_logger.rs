use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use o_dns_lib::DnsPacket;
use serde::Serialize;
use sqlx::prelude::FromRow;
use sqlx::{SqliteConnection, SqlitePool};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{interval, Instant};

use crate::resolver::ResponseSource;

const DEFAULT_LOG_CHUNK: usize = 64;

#[derive(Debug, Serialize, FromRow)]
pub struct LogEntry {
    pub id: u32,
    pub timestamp: u32,
    pub domain: String,
    pub qtype: u16,
    pub client: Option<String>,
    pub response_code: u8,
    pub response_delay_ms: u32,
    pub source: Option<u8>,
}

impl LogEntry {
    pub fn new_from_response(
        response: &DnsPacket<'_>,
        client: Option<IpAddr>,
        response_delay_ms: u32,
        source: Option<ResponseSource>,
    ) -> anyhow::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("bug: misconfigured time on the system")?
            .as_secs() as u32;

        let question = response
            .questions
            .first()
            .context("bug: missing question in the response packet")?;

        Ok(LogEntry {
            id: 0,
            timestamp,
            domain: question.qname.clone().into_owned(),
            qtype: question.query_type.into(),
            client: client.map(|addr| addr.to_string()),
            response_code: response.header.response_code as u8,
            response_delay_ms,
            source: source.map(|src| src as u8),
        })
    }

    async fn insert_into(&self, connection: &mut SqliteConnection) -> anyhow::Result<()> {
        let query_result = sqlx::query(
            "INSERT INTO query_log (timestamp, domain, qtype, client, response_code, response_delay_ms, source)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(self.timestamp)
        .bind(&self.domain)
        .bind(self.qtype)
        .bind(&self.client)
        .bind(self.response_code as u8)
        .bind(self.response_delay_ms)
        .bind(self.source.as_ref().map(|src| *src as u8))
        .execute(connection)
        .await
        .context("error while inserting a log entry")?;

        if query_result.rows_affected() != 1 {
            anyhow::bail!(
                "error while inserting a log entry: wrong number of inserted rows {}",
                query_result.rows_affected()
            )
        }

        Ok(())
    }
}

pub struct QueryLogger {
    connection_pool: SqlitePool,
    log_rx: UnboundedReceiver<LogEntry>,
}

impl QueryLogger {
    pub async fn new(log_rx: UnboundedReceiver<LogEntry>, connection_pool: SqlitePool) -> anyhow::Result<Self> {
        Ok(QueryLogger {
            connection_pool,
            log_rx,
        })
    }

    pub async fn watch_for_logs(mut self) -> anyhow::Result<()> {
        // Try to write every 5 seconds if there are any logs in the queue
        let mut db_write_interval = interval(Duration::from_secs(5));

        let mut logs = Vec::with_capacity(DEFAULT_LOG_CHUNK);
        loop {
            let shut_down = tokio::select! {
                received_logs = self.log_rx.recv_many(&mut logs, DEFAULT_LOG_CHUNK) => {
                    if received_logs == 0 {
                        tracing::debug!("all log senders were dropped, shutting down the query logger");
                        // Send whatever we have left and exit
                        true
                    } else {
                        // Continue collecting the logs until we meet the condition in the second branch
                        continue;
                    }
                }
                _ = db_write_interval.tick() => {
                    if logs.is_empty() {
                        continue;
                    }
                    // It's time to write the collected logs to SQLite
                    false
                }
            };

            let start = Instant::now();
            let mut tx = self
                .connection_pool
                .begin()
                .await
                .context("error while creating a transaction")?;

            for log in logs.iter() {
                log.insert_into(&mut tx)
                    .await
                    .context("error while adding a log to the txn")?;
            }

            tx.commit()
                .await
                .context("error while inserting collected logs into the DB")?;

            tracing::trace!(
                "Stored {} query logs to SQLite in {:.3} seconds",
                logs.len(),
                start.elapsed().as_secs_f64()
            );

            if shut_down {
                break;
            }

            logs.clear();
        }

        Ok(())
    }
}
