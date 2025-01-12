mod list_entry;
mod query_log;
mod stats;

use anyhow::Context as _;
pub use list_entry::{EntryKind, ListEntry, ListEntryUpdateRequest};
pub use query_log::QueryLog;
use serde::Serialize;
use sqlx::sqlite::{SqliteQueryResult, SqliteRow};
use sqlx::{FromRow, SqliteConnection};
pub use stats::StatsEntry;

pub trait Model: Serialize + for<'a> FromRow<'a, SqliteRow> + Sync {
    const NAME: &'static str;

    fn bind_and_insert(
        &self,
        connection: &mut SqliteConnection,
    ) -> impl std::future::Future<Output = anyhow::Result<SqliteQueryResult>> + Send;

    fn bind_and_replace(
        &self,
        connection: &mut SqliteConnection,
    ) -> impl std::future::Future<Output = anyhow::Result<SqliteQueryResult>> + Send;

    fn replace_into(
        &self,
        connection: &mut SqliteConnection,
    ) -> impl std::future::Future<Output = anyhow::Result<u32>> + Send {
        async {
            let result = self
                .bind_and_replace(connection)
                .await
                .with_context(|| format!("error while replacing a {}", Self::NAME))?;

            if result.rows_affected() != 1 {
                anyhow::bail!(
                    "error while replacing a {}: wrong number of affected rows {}",
                    Self::NAME,
                    result.rows_affected()
                )
            }

            Ok(result.last_insert_rowid() as u32)
        }
    }

    fn insert_into(
        &self,
        connection: &mut SqliteConnection,
    ) -> impl std::future::Future<Output = anyhow::Result<u32>> + Send {
        async {
            let result = self
                .bind_and_insert(connection)
                .await
                .with_context(|| format!("error while inserting a {}", Self::NAME))?;

            if result.rows_affected() != 1 {
                anyhow::bail!(
                    "error while inserting a {}: wrong number of affected rows {}",
                    Self::NAME,
                    result.rows_affected()
                )
            }

            Ok(result.last_insert_rowid() as u32)
        }
    }
}

pub trait Updatable<U: Sync + Send>: Model {
    fn bind_and_update(
        connection: &mut SqliteConnection,
        id: u32,
        request: U,
    ) -> impl std::future::Future<Output = anyhow::Result<SqliteQueryResult>> + Send;

    fn update_into(
        connection: &mut SqliteConnection,
        id: u32,
        request: U,
    ) -> impl std::future::Future<Output = anyhow::Result<u32>> + Send {
        async move {
            let result = Self::bind_and_update(connection, id, request)
                .await
                .with_context(|| format!("error while updating a {}", Self::NAME))?;

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
}
