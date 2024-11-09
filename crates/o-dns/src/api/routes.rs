use axum::routing::get;
use axum::Router;

use super::handlers::{get_query_logs, health_check};
use super::ApiState;

pub fn get_router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(health_check))
        .route("/logs", get(get_query_logs))
        .with_state(state)
}
