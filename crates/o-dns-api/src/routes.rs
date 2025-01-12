use std::sync::Arc;

use axum::http::header::CONTENT_TYPE;
use axum::http::Method;
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

use super::ApiState;
use crate::handlers::{
    delete_list_entry, get_list_entries, get_query_logs, get_stats, health_check, modify_list_entry,
};

pub fn get_router(state: ApiState) -> Router {
    let state = Arc::new(state);
    Router::new()
        .route("/", get(health_check))
        .route("/logs", get(get_query_logs))
        .route("/entry", post(modify_list_entry))
        .route("/entry", delete(delete_list_entry))
        .route("/entry", get(get_list_entries))
        .route("/stats", get(get_stats))
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::DELETE])
                .allow_headers([CONTENT_TYPE])
                .allow_origin(Any),
        )
        .with_state(state)
}
