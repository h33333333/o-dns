use std::net::IpAddr;
use std::ops::Deref as _;

use anyhow::Context;
use o_dns_db::{EntryKind, ListEntry, Model};
use regex::Regex;
use sqlx::SqliteConnection;

use super::parsers::{parse_domain_name, parse_label, parse_regex};
use crate::{Denylist, Hosts};

pub(super) trait EntryFromStr {
    async fn process_line(line: &mut str, db: &mut SqliteConnection) -> anyhow::Result<()>;
}

impl EntryFromStr for Hosts {
    async fn process_line(line: &mut str, db: &mut SqliteConnection) -> anyhow::Result<()> {
        let (domain, remaining_line) = parse_domain_name(line).context("failed to parse domain")?;

        let (raw_ip_addr, entry_kind, remaining_line) = {
            let mut it = remaining_line.splitn(2, ' ');
            let raw_ip_addr = it.next().context("missing IP address")?;
            let ip_addr: IpAddr = raw_ip_addr.parse().context("failed to parse IP address")?;
            let entry_kind = match ip_addr {
                IpAddr::V4(_) => EntryKind::AllowA,
                IpAddr::V6(_) => EntryKind::AllowAAAA,
            };
            (raw_ip_addr, entry_kind, it.next().unwrap_or(""))
        };

        let label = parse_label(remaining_line);

        // TODO: add only if there is no other entry for this domain (or use some other approach that gives higher priority to entries that already exist in DB)
        let entry = ListEntry::new(
            Some(domain.deref().into()),
            entry_kind,
            Some(raw_ip_addr.into()),
            label.map(Into::into),
        )
        .context("failed to create a ListEntry")?;

        entry.insert_into(db).await?;

        Ok(())
    }
}

impl EntryFromStr for Denylist {
    async fn process_line(line: &mut str, db: &mut SqliteConnection) -> anyhow::Result<()> {
        let (domain, entry_kind, data, remaining_line) = if line.starts_with('/') {
            // Handle regex
            let (regex_str, remaining_line) = parse_regex(line).context("failed to parse regex")?;

            // Check if regex is okay
            Regex::new(regex_str).map_err(|e| anyhow::anyhow!("failed to compile regex '{}': {}", regex_str, e))?;

            (None, EntryKind::DenyRegex, Some((&*regex_str).into()), remaining_line)
        } else {
            // Handle domain
            let (domain, remaining_line) = parse_domain_name(line).context("failed to parse domain")?;
            (Some((&*domain).into()), EntryKind::Deny, None, remaining_line)
        };

        let label = parse_label(remaining_line);

        let entry =
            ListEntry::new(domain, entry_kind, data, label.map(Into::into)).context("failed to create a ListEntry")?;

        entry.insert_into(db).await?;

        Ok(())
    }
}
