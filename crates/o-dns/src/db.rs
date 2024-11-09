use std::{path::Path, time::Duration};

use anyhow::Context as _;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};

pub async fn get_sqlite_connection_pool(path: &Path) -> anyhow::Result<SqlitePool> {
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
    .execute(&connection_pool)
    .await
    .context("error while initializing the DB")?;

    Ok(connection_pool)
}
