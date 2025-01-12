use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use futures::StreamExt as _;
use o_dns_db::{SqliteDb, StatsEntry};
use serde::Serialize;

use crate::util::{get_failed_requests_count_query, get_log_count_per_source_query};
use crate::ApiState;

#[derive(Serialize)]
struct Stats {
    per_source_stats: HashMap<u8, u64>,
    failed_requests_count: u64,
}

pub async fn handler(State(state): State<Arc<ApiState>>) -> Response {
    let stats = match get_stats_handler(&state.db).await {
        Ok(stats) => stats,
        Err(e) => {
            tracing::debug!("Error while getting stats: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Json(stats).into_response()
}

async fn get_stats_handler(db: &SqliteDb) -> anyhow::Result<Stats> {
    let mut connection = db.get_connection().await?;
    let mut query = get_log_count_per_source_query();

    // Per-source request count
    let mut raw_stats = query.build_query_as::<StatsEntry>().fetch(&mut *connection);
    let mut per_source_stats = HashMap::new();
    while let Some(stats_entry) = raw_stats.next().await {
        let stats_entry = stats_entry.context("error while getting stats from DB")?;
        per_source_stats.insert(stats_entry.source, stats_entry.count);
    }
    drop(raw_stats);

    // Number of failed requests
    let mut query = get_failed_requests_count_query();
    let failed_requests_count = query
        .build_query_scalar::<u64>()
        .fetch_optional(&mut *connection)
        .await
        .context("failed to get the number of failed requests from DB")?
        .context("bug: number of failed requests is missing")?;

    Ok(Stats {
        per_source_stats,
        failed_requests_count,
    })
}
