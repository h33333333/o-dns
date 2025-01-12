mod delete_list_entry;
mod get_list_entries;
mod get_query_logs;
mod get_stats;
mod modify_list_entry;

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{async_trait, Json};
pub use delete_list_entry::handler as delete_list_entry;
pub use get_list_entries::{handler as get_list_entries, ListEntriesFilter};
pub use get_query_logs::{handler as get_query_logs, LatestLogsFilter};
pub use get_stats::handler as get_stats;
pub use modify_list_entry::handler as modify_list_entry;
use serde::Deserialize;

use crate::ApiState;

pub trait ValidatableRequest: Sized {
    type Raw;

    fn validate(raw: Self::Raw) -> anyhow::Result<Self>;
}

pub enum ValidationRejection {
    JsonError(String),
    ValidationError(String),
}

impl IntoResponse for ValidationRejection {
    fn into_response(self) -> Response {
        match self {
            ValidationRejection::JsonError(mut error) => (
                StatusCode::BAD_REQUEST,
                error.insert_str(0, "Error while parsing JSON: "),
            )
                .into_response(),
            ValidationRejection::ValidationError(mut error) => (
                StatusCode::BAD_REQUEST,
                error.insert_str(0, "Error while validating the input data: "),
            )
                .into_response(),
        }
    }
}

pub struct ValidatedJson<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: ValidatableRequest,
    Json<T::Raw>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ValidationRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(raw) = Json::<T::Raw>::from_request(req, state)
            .await
            .map_err(|e| (ValidationRejection::JsonError(e.to_string())))?;
        Ok(ValidatedJson(
            T::validate(raw).map_err(|e| ValidationRejection::ValidationError(e.to_string()))?,
        ))
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Sort {
    Asc,
    #[default]
    Desc,
}

pub async fn health_check(State(_): State<Arc<ApiState>>) -> &'static str {
    "I'm alive"
}
