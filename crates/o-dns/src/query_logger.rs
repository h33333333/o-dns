use std::time::Duration;

use anyhow::Context;
use sqlx::SqlitePool;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{interval, Instant};

use crate::db::LogEntry;

const DEFAULT_LOG_CHUNK: usize = 64;

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
