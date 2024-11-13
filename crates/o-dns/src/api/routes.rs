use std::sync::Arc;

use axum::routing::{delete, get, post};
use axum::Router;

use super::handlers::{add_new_list_entry, delete_list_entry, get_query_logs, health_check};
use super::ApiState;

pub fn get_router(state: ApiState) -> Router {
    let state = Arc::new(state);
    Router::new()
        .route("/", get(health_check))
        .route("/logs", get(get_query_logs))
        .route("/entry", post(add_new_list_entry))
        .route("/entry", delete(delete_list_entry))
        .with_state(state)
}
