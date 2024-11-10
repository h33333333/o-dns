mod query_log;

use anyhow::Context as _;
pub use query_log::QueryLog;
use serde::Serialize;
use sqlx::sqlite::SqliteRow;
use sqlx::{FromRow, SqliteConnection};

pub trait Model: Serialize + for<'a> FromRow<'a, SqliteRow> {
    const NAME: &str;

    async fn bind_and_insert(&self, connection: &mut SqliteConnection) -> anyhow::Result<u64>;

    async fn insert_into(&self, connection: &mut SqliteConnection) -> anyhow::Result<()> {
        let affected_rows = self
            .bind_and_insert(connection)
            .await
            .with_context(|| format!("error while inserting a {}", Self::NAME))?;

        if affected_rows != 1 {
            anyhow::bail!(
                "error while inserting a {}: wrong number of inserted rows {}",
                Self::NAME,
                affected_rows
            )
        }

        Ok(())
    }
}
