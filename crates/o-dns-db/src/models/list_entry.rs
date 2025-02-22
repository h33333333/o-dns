use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::Serialize;
use sqlx::sqlite::{SqliteQueryResult, SqliteRow};
use sqlx::{Decode, FromRow, Row, SqliteConnection};

use super::{Model, Updatable};

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
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
pub struct ListEntry<'a> {
    pub id: u32,
    pub timestamp: u32,
    pub domain: Option<Cow<'a, str>>,
    pub kind: EntryKind,
    pub data: Option<Cow<'a, str>>,
    pub label: Option<Cow<'a, str>>,
}

impl<'a> ListEntry<'a> {
    pub async fn select_all(connection: &mut SqliteConnection) -> anyhow::Result<Vec<ListEntry<'static>>> {
        sqlx::query_as("SELECT * FROM allow_deny_list")
            .fetch_all(connection)
            .await
            .context("failed to select all dynamic allow/deny list entries")
    }
}

impl<'r> FromRow<'r, SqliteRow> for ListEntry<'_> {
    fn from_row(row: &'r SqliteRow) -> Result<ListEntry<'static>, sqlx::Error> {
        let id = row.try_get("id")?;
        let timestamp = row.try_get("timestamp")?;
        let domain: Option<String> = row.try_get("domain")?;
        let kind_raw: u8 = row.try_get("kind")?;
        let data: Option<String> = row.try_get("data")?;
        let label: Option<String> = row.try_get("label")?;

        Ok(ListEntry {
            id,
            timestamp,
            domain: domain.map(Into::into),
            kind: kind_raw
                .try_into()
                .map_err(|_| sqlx::Error::Decode(anyhow::anyhow!("Failed to convert 'kind' to an enum").into()))?,
            data: data.map(Into::into),
            label: label.map(Into::into),
        })
    }
}

impl<'a> ListEntry<'a> {
    pub fn new(
        domain: Option<Cow<'a, str>>,
        kind: EntryKind,
        data: Option<Cow<'a, str>>,
        label: Option<Cow<'a, str>>,
    ) -> anyhow::Result<ListEntry<'a>> {
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
            label,
        })
    }
}

impl Model for ListEntry<'_> {
    const NAME: &'static str = "ListEntry";

    async fn bind_and_insert(&self, connection: &mut SqliteConnection) -> anyhow::Result<SqliteQueryResult> {
        sqlx::query(
            "INSERT INTO allow_deny_list (timestamp, domain, kind, data, label)
            SELECT ?1, ?2, ?3, ?4, ?5
            WHERE NOT EXISTS (
                SELECT 1 FROM allow_deny_list
                WHERE (domain IS NULL AND ?2 IS NULL OR domain = ?2)
                AND (kind IS NULL AND ?3 IS NULL OR kind = ?3)
                AND (data IS NULL AND ?4 IS NULL OR data = ?4)
            )
            ",
        )
        .bind(self.timestamp)
        .bind(&self.domain)
        .bind(self.kind as u8)
        .bind(&self.data)
        .bind(&self.label)
        .execute(connection)
        .await
        .context("error while inserting a list entry")
    }

    async fn bind_and_replace(&self, connection: &mut SqliteConnection) -> anyhow::Result<SqliteQueryResult> {
        sqlx::query(
            "REPLACE INTO allow_deny_list (id, timestamp, domain, kind, data, label)
            VALUES ((SELECT id FROM allow_deny_list WHERE ((domain is NULL AND ?2 IS NULL) OR domain = ?2) AND kind = ?3 AND ((data is NULL AND ?4 IS NULL) OR data = ?4)), ?1, ?2, ?3, ?4, ?5)",
        )
        .bind(self.timestamp)
        .bind(&self.domain)
        .bind(self.kind as u8)
        .bind(&self.data)
        .bind(&self.label)
        .execute(connection)
        .await
        .context("error while inserting a list entry")
    }
}

pub struct ListEntryUpdateRequest<'a> {
    pub kind: EntryKind,
    pub domain: Option<Cow<'a, str>>,
    pub data: Option<Cow<'a, str>>,
    pub label: Option<Cow<'a, str>>,
}

impl<'a> ListEntryUpdateRequest<'a> {
    pub fn new(
        kind: EntryKind,
        domain: Option<Cow<'a, str>>,
        data: Option<Cow<'a, str>>,
        label: Option<Cow<'a, str>>,
    ) -> Self {
        ListEntryUpdateRequest {
            kind,
            domain,
            data,
            label,
        }
    }
}

impl<'a> Updatable<ListEntryUpdateRequest<'a>> for ListEntry<'_> {
    async fn bind_and_update(
        connection: &mut SqliteConnection,
        id: u32,
        request: ListEntryUpdateRequest<'a>,
    ) -> anyhow::Result<SqliteQueryResult> {
        if request.data.is_none() && request.domain.is_none() && request.label.is_none() {
            anyhow::bail!("Wrong update request: no field was changed")
        }

        sqlx::query("UPDATE allow_deny_list SET kind = ?1, domain = ?2, data = ?3, label = ?4 WHERE id = ?5")
            .bind(request.kind as u8)
            .bind(request.domain)
            .bind(request.data)
            .bind(request.label)
            .bind(id)
            .execute(connection)
            .await
            .context("error while updating a list entry")
    }
}
