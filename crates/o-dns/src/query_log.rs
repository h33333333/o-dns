use std::{
    net::IpAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use o_dns_lib::{DnsPacket, ResponseCode};
use rusqlite::Connection;
use tokio::{
    sync::mpsc::UnboundedReceiver,
    task::yield_now,
    time::{interval, Instant},
};

use crate::resolver::ResponseSource;

const DEFAULT_LOG_CHUNK: usize = 64;

#[derive(Debug)]
pub struct LogEntry {
    pub id: u32,
    pub timestamp: u32,
    pub domain: String,
    pub qtype: u16,
    pub client: Option<String>,
    pub response_code: ResponseCode,
    pub response_delay_ms: u32,
    pub source: Option<ResponseSource>,
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
            .get(0)
            .context("bug: missing question in the response packet")?;

        Ok(LogEntry {
            id: 0,
            timestamp,
            domain: question.qname.clone().into_owned(),
            qtype: question.query_type.into(),
            client: client.map(|addr| addr.to_string()),
            response_code: response.header.response_code,
            response_delay_ms,
            source,
        })
    }

    fn insert_into(&self, connection: &Connection) -> anyhow::Result<()> {
        let inserted_rows = connection.execute(
            "INSERT INTO query_log (timestamp, domain, qtype, client, response_code, response_delay_ms, source)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                &self.timestamp,
                &self.domain,
                &self.qtype,
                &self.client,
                self.response_code as u8,
                &self.response_delay_ms,
                self.source.as_ref().map(|src| *src as u8)
            )
        ).context("error while inserting a log entry")?;

        if inserted_rows != 1 {
            anyhow::bail!(
                "error while inserting a log entry: wrong number of inserted rows {}",
                inserted_rows
            )
        }

        Ok(())
    }
}

pub struct QueryLogger {
    connection: Connection,
    log_rx: UnboundedReceiver<LogEntry>,
}

impl QueryLogger {
    pub fn new(log_rx: UnboundedReceiver<LogEntry>, path: &Path) -> anyhow::Result<Self> {
        let path = path.with_file_name("query_log.db");

        // Ensure that all directories exist
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new("/")))
            .context("error while creating parent directories for the query log DB")?;

        let connection =
            Connection::open(path).context("error while opening a connection to SQLite DB")?;

        connection
            .execute(
                "CREATE TABLE IF NOT EXISTS query_log (
                    id INTEGER PRIMARY KEY,
                    timestamp INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    qtype INTEGER NOT NULL,
                    client TEXT,
                    response_code INTEGER NOT NULL,
                    response_delay_ms INTEGER NOT NULL,
                    source INTEGER
                )",
                (),
            )
            .context("error while creating a table")?;

        Ok(QueryLogger { connection, log_rx })
    }

    pub async fn watch_for_logs(mut self) -> anyhow::Result<()> {
        // Try to write every 500 ms if there are enough logs in the queue
        let mut db_write_interval = interval(Duration::from_millis(500));

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
                _ = db_write_interval.tick(), if logs.len() >= DEFAULT_LOG_CHUNK => {
                    // It's time to write the collected logs to SQLite
                    false
                }
            };

            let start = Instant::now();
            let tx = self
                .connection
                .transaction()
                .context("error while creating a transaction")?;

            yield_now().await;

            for log in logs.iter() {
                log.insert_into(&tx)
                    .context("error while adding a log to the txn")?;

                yield_now().await;
            }

            tx.commit()
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
