use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use o_dns_lib::DnsPacket;
use serde::Serialize;
use sqlx::{FromRow, SqliteConnection};

use super::Model;
use crate::resolver::ResponseSource;

#[derive(Debug, Serialize, FromRow)]
pub struct QueryLog {
    pub id: u32,
    pub timestamp: u32,
    pub domain: String,
    pub qtype: u16,
    pub client: Option<String>,
    pub response_code: u8,
    pub response_delay_ms: u32,
    pub source: Option<u8>,
}

impl QueryLog {
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
            .first()
            .context("bug: missing question in the response packet")?;

        Ok(QueryLog {
            id: 0,
            timestamp,
            domain: question.qname.clone().into_owned(),
            qtype: question.query_type.into(),
            client: client.map(|addr| addr.to_string()),
            response_code: response.header.response_code as u8,
            response_delay_ms,
            source: source.map(|src| src as u8),
        })
    }
}

impl Model for QueryLog {
    const NAME: &str = "LogEntry";

    async fn bind_and_insert(&self, connection: &mut SqliteConnection) -> anyhow::Result<u64> {
        sqlx::query(
            "INSERT INTO query_log (timestamp, domain, qtype, client, response_code, response_delay_ms, source)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(self.timestamp)
        .bind(&self.domain)
        .bind(self.qtype)
        .bind(&self.client)
        .bind(self.response_code)
        .bind(self.response_delay_ms)
        .bind(self.source.as_ref().map(|src| *src))
        .execute(connection)
        .await
        .context("error while inserting a log entry")
        .map(|result| result.rows_affected())
    }
}
