use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use o_dns_common::{hash_to_u128, AccessListEntryKind, DnsServerCommand};
use o_dns_db::{EntryKind, ListEntry, ListEntryUpdateRequest, Model as _, Updatable as _};
use regex::Regex;
use serde::Deserialize;
use tokio::sync::mpsc::Sender;

use super::ValidatableRequest;
use crate::handlers::ValidatedJson;
use crate::util::build_select_list_entry_by_id;
use crate::ApiState;

#[derive(Debug, Deserialize)]
pub struct RawListEntryRequest {
    pub id: Option<u32>,
    pub kind: u8,
    pub domain: Option<String>,
    pub data: Option<String>,
    pub label: Option<String>,
}

pub struct ModifyListEntryRequest {
    pub id: Option<u32>,
    pub kind: EntryKind,
    pub cmd: AccessListEntryKind,
    pub domain: Option<String>,
    pub data: Option<String>,
    pub label: Option<String>,
}

impl ValidatableRequest for ModifyListEntryRequest {
    type Raw = RawListEntryRequest;

    fn validate(raw: Self::Raw) -> anyhow::Result<Self> {
        // Validate kind
        let kind: EntryKind = match raw.kind.try_into() {
            Ok(kind) => kind,
            Err(_) => {
                tracing::debug!("Invalid entry kind: {}", raw.kind);
                anyhow::bail!("Unsupported 'kind'");
            }
        };

        // Validate all other fields and turn them into a DNS server command
        let domain = raw.domain.as_ref().map(|domain| hash_to_u128(domain, None));
        let cmd = match kind {
            EntryKind::Deny => AccessListEntryKind::DenyDomain(domain.context("Missing 'domain' for a deny entry")?),
            EntryKind::DenyRegex => {
                let regex = match Regex::new(
                    raw.data
                        .as_ref()
                        .context("Missing 'data' for a deny entry with regex")?,
                ) {
                    Ok(regex) => regex,
                    Err(e) => {
                        anyhow::bail!("Invalid regex: {:#}", e);
                    }
                };

                AccessListEntryKind::DenyRegex((0, Some(regex)))
            }
            EntryKind::AllowA | EntryKind::AllowAAAA => {
                let raw_ip = raw.data.as_ref().context("Missing 'data' for an allow entry")?;

                let ip = match raw_ip.parse::<IpAddr>() {
                    Ok(ip) => ip,
                    Err(_) => {
                        anyhow::bail!("Invalid 'data' for the specified 'kind'")
                    }
                };

                AccessListEntryKind::Hosts((domain.context("Missing 'domain' for a hosts entry")?, ip))
            }
        };

        Ok(ModifyListEntryRequest {
            id: raw.id,
            kind,
            cmd,
            domain: raw.domain,
            data: raw.data,
            label: raw.label,
        })
    }
}

pub async fn handler(
    State(state): State<Arc<ApiState>>,
    ValidatedJson(request): ValidatedJson<ModifyListEntryRequest>,
) -> Response {
    if let Err(e) = process_request(state, request).await {
        tracing::debug!("Error while modifying a list entry: {:#}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    StatusCode::OK.into_response()
}

async fn process_request(state: Arc<ApiState>, request: ModifyListEntryRequest) -> anyhow::Result<()> {
    let mut connection = state.db.get_connection().await?;

    let mut cmd = Some(request.cmd);
    let id = if let Some(id) = request.id {
        // We are modifying an existing entry
        let mut query = build_select_list_entry_by_id(id);
        let entry = query
            .build_query_as::<ListEntry>()
            .fetch_one(&mut *connection)
            .await
            .context("trying to edit a non-existing entry")?;

        // Update entry on the server only if any non-label field was changed
        if request.domain.as_deref() != entry.domain.as_deref()
            || request.data.as_deref() != entry.data.as_deref()
            || request.kind != entry.kind
        {
            // Delete the existing entry in the DNS server
            delete_existing_entry(
                id,
                entry.domain.as_deref(),
                entry.kind,
                entry.data.as_deref(),
                &state.command_tx,
            )
            .await
            .context("error while deleting the existing entry on the DNS server side")?;
        } else {
            // Avoid updating server if label is the only changed field
            cmd = None;
        }

        // Update the entry in DB
        let update_request = ListEntryUpdateRequest::new(
            request.kind,
            request.domain.map(Into::into),
            request.data.map(Into::into),
            request.label.map(Into::into),
        );
        ListEntry::update_into(&mut connection, id, update_request).await?;

        id
    } else {
        // We are adding a new entry
        let entry = ListEntry::new(
            request.domain.map(Into::into),
            request.kind,
            request.data.map(Into::into),
            request.label.map(Into::into),
        )?;
        entry.replace_into(&mut connection).await?
    };

    if let Some(mut cmd) = cmd {
        if let AccessListEntryKind::DenyRegex(cmd) = &mut cmd {
            // Assign a proper id to the regex so that it can be deleted later
            cmd.0 = id;
        }

        let _ = state.command_tx.send(DnsServerCommand::AddNewListEntry(cmd)).await;
    }

    Ok(())
}

async fn delete_existing_entry(
    id: u32,
    domain: Option<&str>,
    kind: EntryKind,
    data: Option<&str>,
    command_tx: &Sender<DnsServerCommand>,
) -> anyhow::Result<()> {
    // Delete the existing entry in the DNS server
    let domain = domain.map(|domain| hash_to_u128(domain, None));
    let cmd = DnsServerCommand::RemoveListEntry(match kind {
        EntryKind::Deny => AccessListEntryKind::DenyDomain(domain.context("bug: missing 'domain' for a Deny entry?")?),
        EntryKind::DenyRegex => AccessListEntryKind::DenyRegex((id, None)),
        EntryKind::AllowA | EntryKind::AllowAAAA => AccessListEntryKind::Hosts((
            domain.context("bug: missing 'domain' for a Hosts entry?")?,
            data.context("bug: missing 'data' for a Hosts entry?")?
                .parse()
                .context("bug: failed to parse IpAddr from 'data'?")?,
        )),
    });

    let _ = command_tx.send(cmd).await;

    Ok(())
}
