use serde::Serialize;
use sqlx::sqlite::SqliteRow;
use sqlx::{Decode, FromRow, Row};

#[derive(Debug, Serialize, Decode)]
pub struct StatsEntry {
    pub source: u8,
    pub count: u64,
}

impl<'r> FromRow<'r, SqliteRow> for StatsEntry {
    fn from_row(row: &'r SqliteRow) -> Result<StatsEntry, sqlx::Error> {
        let source = row.try_get("source")?;
        let count = row.try_get("count")?;

        Ok(StatsEntry { source, count })
    }
}
