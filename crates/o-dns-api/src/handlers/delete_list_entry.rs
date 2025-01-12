use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use futures::StreamExt as _;
use o_dns_common::{hash_to_u128, AccessListEntryKind, DnsServerCommand};
use o_dns_db::{EntryKind, ListEntry};

use crate::util::build_delete_list_entries_query;
use crate::ApiState;

pub async fn handler(State(state): State<Arc<ApiState>>, Json(ids): Json<Vec<u32>>) -> Response {
    match delete_list_entry_handler(state, &ids).await {
        Ok(()) => (),
        Err(e) => {
            tracing::debug!(ids = ?ids, "Error while deleting a list entry: {:#}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    StatusCode::OK.into_response()
}

async fn delete_list_entry_handler(state: Arc<ApiState>, ids: &[u32]) -> anyhow::Result<()> {
    let mut query = build_delete_list_entries_query(ids);

    let mut connection = state.db.get_connection().await?;

    let mut deleted_entries = query.build_query_as::<ListEntry>().fetch(&mut *connection);

    while let Some(entry) = deleted_entries.next().await {
        let entry = entry.context("failed to delete a list entry")?;

        let domain = entry.domain.as_ref().map(|domain| hash_to_u128(domain.as_ref(), None));
        let cmd = DnsServerCommand::RemoveListEntry(match entry.kind {
            EntryKind::Deny => {
                AccessListEntryKind::DenyDomain(domain.context("bug: missing 'domain' for a Deny entry?")?)
            }
            EntryKind::DenyRegex => AccessListEntryKind::DenyRegex((entry.id, None)),
            EntryKind::AllowA | EntryKind::AllowAAAA => AccessListEntryKind::Hosts((
                domain.context("bug: missing 'domain' for a Hosts entry?")?,
                entry
                    .data
                    .as_ref()
                    .context("bug: missing 'data' for a Hosts entry?")?
                    .parse()
                    .context("bug: failed to parse IpAddr from 'data'?")?,
            )),
        });

        let _ = state.command_tx.send(cmd).await;
    }

    Ok(())
}
