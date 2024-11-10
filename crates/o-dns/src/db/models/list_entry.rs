use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::Serialize;
use sqlx::sqlite::SqliteRow;
use sqlx::{Decode, FromRow, Row, SqliteConnection};

use super::Model;

#[derive(Debug, Serialize, Clone, Copy)]
pub enum EntryKind {
    Deny,
    DenyRegex,
    AllowA,
    AllowAAAA,
}

impl TryFrom<u8> for EntryKind {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EntryKind::Deny),
            1 => Ok(EntryKind::DenyRegex),
            2 => Ok(EntryKind::AllowA),
            3 => Ok(EntryKind::AllowAAAA),
            _ => Err("Out of bound value for EntryType"),
        }
    }
}

#[derive(Debug, Serialize, Decode)]
pub struct ListEntry {
    pub id: u32,
    pub timestamp: u32,
    pub domain: String,
    pub kind: EntryKind,
    pub data: String,
}

impl<'r> FromRow<'r, SqliteRow> for ListEntry {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let id = row.try_get("id")?;
        let timestamp = row.try_get("timestamp")?;
        let domain = row.try_get("domain")?;
        let kind_raw: u8 = row.try_get("kind")?;
        let data = row.try_get("data")?;

        Ok(ListEntry {
            id,
            timestamp,
            domain,
            kind: kind_raw
                .try_into()
                .map_err(|_| sqlx::Error::Decode(anyhow::anyhow!("Failed to convert 'kind' to an enum").into()))?,
            data,
        })
    }
}

impl ListEntry {
    pub fn new(domain: String, kind: EntryKind, data: String) -> anyhow::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("bug: misconfigured time on the system")?
            .as_secs() as u32;

        Ok(ListEntry {
            id: 0,
            timestamp,
            domain,
            kind,
            data,
        })
    }
}

impl Model for ListEntry {
    const NAME: &str = "LogEntry";
    const TABLE: &str = "allow_deny_list";

    async fn bind_and_insert(&self, connection: &mut SqliteConnection) -> anyhow::Result<u64> {
        sqlx::query(
            "INSERT INTO ?1 (timestamp, domain, kind, data)
            VALUES (?2, ?3, ?4, ?5)",
        )
        .bind(Self::TABLE)
        .bind(self.timestamp)
        .bind(&self.domain)
        .bind(self.kind as u8)
        .bind(&self.data)
        .execute(connection)
        .await
        .context("error while inserting a log entry")
        .map(|result| result.rows_affected())
    }
}
