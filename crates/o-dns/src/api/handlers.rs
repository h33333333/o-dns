use anyhow::Context;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use serde::Deserialize;
use sqlx::SqlitePool;

use super::util::build_select_query_with_filters;
use super::ApiState;
use crate::query_logger::LogEntry;

pub async fn health_check(State(_): State<ApiState>) -> &'static str {
    "I'm alive"
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

pub async fn get_query_logs(State(state): State<ApiState>, Query(filter): Query<LatestLogsFilter>) -> Response {
    let logs = match get_latest_logs_handler(state.connection_pool, &filter).await {
        Ok(logs) => logs,
        Err(e) => {
            tracing::debug!(filter = ?filter, "Error while getting latest logs: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Json(logs).into_response()
}

async fn get_latest_logs_handler(
    connection_pool: SqlitePool,
    filter: &LatestLogsFilter,
) -> anyhow::Result<Vec<LogEntry>> {
    let mut query = build_select_query_with_filters(filter);

    let logs: Vec<LogEntry> = query
        .build_query_as()
        .fetch_all(&connection_pool)
        .await
        .context("failed to get data from DB")?;

    Ok(logs)
}
