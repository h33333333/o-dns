mod list_entry;
mod query_log;

use anyhow::Context as _;
pub use list_entry::{EntryKind, ListEntry};
pub use query_log::QueryLog;
use serde::Serialize;
use sqlx::sqlite::{SqliteQueryResult, SqliteRow};
use sqlx::{FromRow, SqliteConnection};

pub trait Model: Serialize + for<'a> FromRow<'a, SqliteRow> {
    const NAME: &str;

    async fn bind_and_insert(&self, connection: &mut SqliteConnection) -> anyhow::Result<SqliteQueryResult>;

    async fn bind_and_replace(&self, connection: &mut SqliteConnection) -> anyhow::Result<SqliteQueryResult>;

    async fn replace_into(&self, connection: &mut SqliteConnection) -> anyhow::Result<u32> {
        let result = self
            .bind_and_replace(connection)
            .await
            .with_context(|| format!("error while inserting a {}", Self::NAME))?;

        if result.rows_affected() != 1 {
            anyhow::bail!(
                "error while inserting a {}: wrong number of inserted rows {}",
                Self::NAME,
                result.rows_affected()
            )
        }

        Ok(result.last_insert_rowid() as u32)
    }

    async fn insert_into(&self, connection: &mut SqliteConnection) -> anyhow::Result<u32> {
        let result = self
            .bind_and_insert(connection)
            .await
            .with_context(|| format!("error while inserting a {}", Self::NAME))?;

        if result.rows_affected() != 1 {
            anyhow::bail!(
                "error while inserting a {}: wrong number of inserted rows {}",
                Self::NAME,
                result.rows_affected()
            )
        }

        Ok(result.last_insert_rowid() as u32)
    }
}
