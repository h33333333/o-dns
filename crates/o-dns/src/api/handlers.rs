use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use regex::Regex;
use serde::Deserialize;

use super::util::{build_delete_list_entry_query, build_select_logs_query_with_filters};
use super::ApiState;
use crate::db::{EntryKind, ListEntry, Model as _, QueryLog, SqliteDb};
use crate::hosts::ListEntryKind;
use crate::server::DnsServerCommand;
use crate::util::hash_to_u128;

pub async fn health_check(State(_): State<Arc<ApiState>>) -> &'static str {
    "I'm alive"
}

#[derive(Debug, Deserialize)]
pub struct ListEntryBody {
    pub kind: u8,
    pub domain: Option<String>,
    pub data: Option<String>,
    pub label: Option<String>,
}

pub async fn add_new_list_entry(State(state): State<Arc<ApiState>>, Json(entry): Json<ListEntryBody>) -> Response {
    let kind: EntryKind = match entry.kind.try_into() {
        Ok(kind) => kind,
        Err(_) => {
            tracing::debug!("Invalid entry kind: {}", entry.kind);
            return (StatusCode::BAD_REQUEST, "Invalid 'kind'").into_response();
        }
    };

    let domain = entry.domain.as_ref().map(|domain| hash_to_u128(domain, None));
    // Validate data
    let mut cmd = DnsServerCommand::AddNewListEntry(match kind {
        EntryKind::Deny => {
            let Some(domain) = domain else {
                return (StatusCode::BAD_REQUEST, "Missing 'domain' for a deny entry").into_response();
            };
            ListEntryKind::DenyDomain(domain)
        }
        EntryKind::DenyRegex => {
            let Some(regex) = entry.data.as_ref() else {
                return (StatusCode::BAD_REQUEST, "Missing 'data' for a deny entry with regex").into_response();
            };
            let regex = match Regex::new(regex) {
                Ok(regex) => regex,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("Invalid regex: {:#}", e)).into_response();
                }
            };
            ListEntryKind::DenyRegex((0, Some(regex)))
        }
        EntryKind::AllowA | EntryKind::AllowAAAA => {
            let Some(domain) = domain else {
                return (StatusCode::BAD_REQUEST, "Missing 'domain' for a hosts entry").into_response();
            };
            let Some(ip) = entry.data.as_ref() else {
                return (StatusCode::BAD_REQUEST, "Missing 'data' for an allow entry").into_response();
            };
            let ip = match ip.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    return (StatusCode::BAD_REQUEST, "Invalid 'data' for the specified 'kind'").into_response();
                }
            };
            ListEntryKind::Hosts((domain, ip))
        }
    });

    if let Err(e) = async move {
        let mut connection = state.db.get_connection().await?;

        let entry = ListEntry::new(
            entry.domain.map(Into::into),
            kind,
            entry.data.map(Into::into),
            entry.label.map(Into::into),
        )?;
        let id = entry.replace_into(&mut connection).await?;

        if let DnsServerCommand::AddNewListEntry(ListEntryKind::DenyRegex(cmd)) = &mut cmd {
            // Assign a proper id to the regex so that it can later be deleted
            cmd.0 = id;
        }

        let _ = state.command_tx.send(cmd).await;

        Ok::<(), anyhow::Error>(())
    }
    .await
    {
        tracing::debug!("Error while adding a new list entry: {:#}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    StatusCode::OK.into_response()
}

#[derive(Debug, Deserialize)]
pub struct LatestLogsFilter {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub from_timestamp: Option<u32>,
    #[serde(default)]
    pub sort: Sort,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Sort {
    Asc,
    #[default]
    Desc,
}

pub async fn get_query_logs(State(state): State<Arc<ApiState>>, Query(filter): Query<LatestLogsFilter>) -> Response {
    let logs = match get_latest_logs_handler(&state.db, &filter).await {
        Ok(logs) => logs,
        Err(e) => {
            tracing::debug!(filter = ?filter, "Error while getting latest logs: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Json(logs).into_response()
}

async fn get_latest_logs_handler(db: &SqliteDb, filter: &LatestLogsFilter) -> anyhow::Result<Vec<QueryLog>> {
    let mut query = build_select_logs_query_with_filters(filter);

    let mut connection = db.get_connection().await?;

    let logs: Vec<QueryLog> = query
        .build_query_as()
        .fetch_all(&mut *connection)
        .await
        .context("failed to get data from DB")?;

    Ok(logs)
}

#[derive(Debug, Deserialize)]
pub struct DeleteListEntryParams {
    pub id: u32,
}

pub async fn delete_list_entry(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<DeleteListEntryParams>,
) -> Response {
    match delete_list_entry_handler(state, params.id).await {
        Ok(()) => (),
        Err(e) => {
            tracing::debug!(filter = ?params, "Error while deleting a list entry: {:#}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    StatusCode::OK.into_response()
}

async fn delete_list_entry_handler(state: Arc<ApiState>, id: u32) -> anyhow::Result<()> {
    let mut query = build_delete_list_entry_query(id);

    let mut connection = state.db.get_connection().await?;

    let Some(deleted_entry) = query
        .build_query_as::<'_, ListEntry>()
        .fetch_optional(&mut *connection)
        .await
        .context("failed to delete the list entry")?
    else {
        anyhow::bail!("non-existing list entry");
    };

    let domain = deleted_entry.domain.map(|domain| hash_to_u128(domain.as_ref(), None));
    let cmd = DnsServerCommand::RemoveListEntry(match deleted_entry.kind {
        EntryKind::Deny => ListEntryKind::DenyDomain(domain.context("bug: missing 'domain' for a Deny entry?")?),
        EntryKind::DenyRegex => ListEntryKind::DenyRegex((id, None)),
        EntryKind::AllowA | EntryKind::AllowAAAA => ListEntryKind::Hosts((
            domain.context("bug: missing 'domain' for a Hosts entry?")?,
            deleted_entry
                .data
                .context("bug: missing 'data' for a Hosts entry?")?
                .parse()
                .context("bug: failed to parse IpAddr from 'data'?")?,
        )),
    });

    let _ = state.command_tx.send(cmd).await;

    Ok(())
}
