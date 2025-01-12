use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use o_dns_db::{ListEntry, SqliteDb};
use serde::Deserialize;

use super::Sort;
use crate::util::build_select_list_entries_with_filters;
use crate::ApiState;

#[derive(Debug, Deserialize)]
pub struct ListEntriesFilter {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    #[serde(default)]
    pub sort: Sort,
}

pub async fn handler(State(state): State<Arc<ApiState>>, Query(filter): Query<ListEntriesFilter>) -> Response {
    let logs = match get_list_entries_handler(&state.db, &filter).await {
        Ok(logs) => logs,
        Err(e) => {
            tracing::debug!(filter = ?filter, "Error while getting latest logs: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Json(logs).into_response()
}

async fn get_list_entries_handler(
    db: &SqliteDb,
    filter: &ListEntriesFilter,
) -> anyhow::Result<Vec<ListEntry<'static>>> {
    let mut query = build_select_list_entries_with_filters(filter);

    let mut connection = db.get_connection().await?;

    let logs: Vec<ListEntry> = query
        .build_query_as()
        .fetch_all(&mut *connection)
        .await
        .context("failed to get data from DB")?;

    Ok(logs)
}
