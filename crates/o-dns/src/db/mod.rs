mod models;
use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
pub use models::{ListEntry, Model, QueryLog};
use sqlx::pool::PoolConnection;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Sqlite, SqlitePool, Transaction};

#[derive(Debug, Clone)]
pub struct SqliteDb {
    connection_pool: SqlitePool,
}

impl SqliteDb {
    pub async fn new(path: &Path) -> anyhow::Result<Self> {
        let path = path.with_file_name("query_log.db");

        // Ensure that all directories exist
        tokio::fs::create_dir_all(path.parent().unwrap_or(Path::new("/")))
            .await
            .context("error while creating parent directories for the query log DB")?;

        let connect_options = SqliteConnectOptions::new().create_if_missing(true).filename(&path);

        let connection_pool = SqlitePoolOptions::new()
            .min_connections(3)
            .max_connections(10)
            .max_lifetime(Duration::from_secs(60 * 60 * 8))
            .connect_with(connect_options)
            .await
            .context("error while opening a connection to SQLite DB")?;

        Ok(SqliteDb { connection_pool })
    }

    pub async fn init_tables(&self) -> anyhow::Result<()> {
        sqlx::query(
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
        )
        .execute(&self.connection_pool)
        .await
        .context("error while initializing the 'query_log' table")?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS allow_deny_list (
                id INTEGER PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                domain TEXT NOT NULL,
                kind INTEGER NOT NULL,
                data TEXT NOT NULL
            )",
        )
        .execute(&self.connection_pool)
        .await
        .context("error while initializing the 'allow_deny_list' table")?;

        Ok(())
    }

    pub async fn get_connection(&self) -> anyhow::Result<PoolConnection<Sqlite>> {
        self.connection_pool
            .acquire()
            .await
            .context("failed to acquire a connection from pool")
    }

    /// It is the responsibility of the caller to commit the transaction.
    pub async fn begin_transaction(&self) -> anyhow::Result<Transaction<Sqlite>> {
        self.connection_pool
            .begin()
            .await
            .context("failed to start a transaction")
    }
}
