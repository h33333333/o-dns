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

pub async fn health_check(State(_): State<Arc<ApiState>>) -> &'static str {
    "I'm alive"
}

#[derive(Debug, Deserialize)]
pub struct ListEntryBody {
    pub kind: u8,
    pub domain: Option<String>,
    pub data: String,
}

#[axum::debug_handler]
pub async fn add_new_list_entry(State(state): State<Arc<ApiState>>, Json(entry): Json<ListEntryBody>) -> Response {
    let kind: EntryKind = match entry.kind.try_into() {
        Ok(kind) => kind,
        Err(_) => {
            tracing::debug!("Invalid entry kind: {}", entry.kind);
            return (StatusCode::BAD_REQUEST, "Invalid 'kind'").into_response();
        }
    };

    // Validate data
    let cmd = match kind {
        EntryKind::Deny => {
            let Some(domain) = entry.domain.clone() else {
                return (StatusCode::BAD_REQUEST, "Missing 'domain' for a deny entry").into_response();
            };
            DnsServerCommand::AddNewListEntry(ListEntryKind::DenyDomain(domain))
        }
        EntryKind::DenyRegex => {
            let regex = match Regex::new(&entry.data) {
                Ok(regex) => regex,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("Invalid regex: {:#}", e)).into_response();
                }
            };
            DnsServerCommand::AddNewListEntry(ListEntryKind::DenyRegex(regex))
        }
        EntryKind::AllowA | EntryKind::AllowAAAA => {
            let Some(domain) = entry.domain.clone() else {
                return (StatusCode::BAD_REQUEST, "Missing 'domain' for a hosts entry").into_response();
            };
            let ip = match entry.data.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    return (StatusCode::BAD_REQUEST, "Invalid 'data' for the specified 'kind'").into_response();
                }
            };
            DnsServerCommand::AddNewListEntry(ListEntryKind::Hosts((domain, ip)))
        }
    };

    if let Err(e) = async move {
        let mut connection = state.db.get_connection().await?;

        let _ = state.command_tx.send(cmd).await;

        let entry = ListEntry::new(entry.domain, kind, entry.data)?;
        entry.insert_into(&mut connection).await?;

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
    match delete_list_entry_handler(&state.db, params.id).await {
        Ok(()) => (),
        Err(e) => {
            tracing::debug!(filter = ?params, "Error while deleting a list entry: {:#}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    StatusCode::OK.into_response()
}

async fn delete_list_entry_handler(db: &SqliteDb, id: u32) -> anyhow::Result<()> {
    let mut query = build_delete_list_entry_query(id);

    let mut connection = db.get_connection().await?;

    let _deleted_entry: Option<ListEntry> = query
        .build_query_as()
        .fetch_optional(&mut *connection)
        .await
        .context("failed to delete the list entry")?;

    Ok(())
}
