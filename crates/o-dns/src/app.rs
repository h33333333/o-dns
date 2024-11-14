use std::net::{IpAddr, SocketAddr};

use anyhow::Context as _;
use clap::Parser as _;
use regex::Regex;
use sqlx::SqliteConnection;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinSet;

use crate::api::ApiServer;
use crate::db::{EntryKind, ListEntry, SqliteDb};
use crate::hosts::ListEntryKind;
use crate::query_logger::QueryLogger;
use crate::server::DnsServerCommand;
use crate::util::{parse_denylist_file, parse_hosts_file};
use crate::{Args, DnsServer};

pub struct App;

impl App {
    pub async fn run_until_completion() -> anyhow::Result<()> {
        let args = Args::parse();

        let dns_bind_addr = SocketAddr::new(args.host, args.port);
        let upstream_resolver_addr = SocketAddr::new(args.upstream_resolver, args.upstream_port);

        // Channel for query logs
        let (log_tx, log_rx) = unbounded_channel();

        let sqlite_db = SqliteDb::new(&args.query_log_path)
            .await
            .context("failed to establish an SQLite DB connection")?;

        sqlite_db
            .init_tables()
            .await
            .context("failed to initialize DB tables")?;

        // Feed deny and hosts files into the DB
        let mut txn = sqlite_db.begin_transaction().await?;
        if let Some(path) = args.denylist_path.as_ref() {
            parse_denylist_file(path, &mut txn)
                .await
                .context("error while parsing the denylist file")?;
        }
        if let Some(path) = args.allowlist_path.as_ref() {
            parse_hosts_file(path, &mut txn)
                .await
                .context("error while parsing the hosts file")?;
        }
        txn.commit()
            .await
            .context("failed to commit entries from denylist and hosts files")?;

        let query_logger = QueryLogger::new(log_rx, sqlite_db.clone())
            .await
            .context("error while creating a query logger")?;

        // I doubt there will ever be more than 5 commands sitting in this queue at once
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(5);
        let server = DnsServer::new_with_workers(
            dns_bind_addr,
            upstream_resolver_addr,
            log_tx,
            args.max_parallel_connections,
            command_rx,
        )
        .await
        .context("failed to instantiate the DNS server")?;

        // Fill hosts and denylist with additional data from DB
        let mut connection = sqlite_db.get_connection().await?;
        for entry in App::get_dynamic_list_entries(&mut connection).await? {
            if let Err(e) = server.process_command(DnsServerCommand::AddNewListEntry(entry)).await {
                tracing::debug!("Failed to add a list entry: {:#}", e);
            }
        }

        let mut tasks = JoinSet::new();
        tasks.spawn(server.block_until_completion());
        tasks.spawn(query_logger.watch_for_logs());
        if !args.disable_api_server {
            let api_server_bind_addr = SocketAddr::new(args.host, args.api_server_port);
            let api_server = ApiServer::new(sqlite_db, command_tx);
            tasks.spawn(api_server.serve(api_server_bind_addr));
        }

        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result.context("failed to execute a task")? {
                tracing::debug!("Error: {:#}", e);
            }
        }

        Ok(())
    }

    async fn get_dynamic_list_entries(
        connection: &mut SqliteConnection,
    ) -> anyhow::Result<impl Iterator<Item = ListEntryKind>> {
        let dynamic_entries = ListEntry::select_all(connection).await?;

        Ok(dynamic_entries.into_iter().filter_map(|entry| {
            Some(match entry.kind {
                EntryKind::Deny => ListEntryKind::DenyDomain(entry.domain?.into_owned()),
                EntryKind::DenyRegex => ListEntryKind::DenyRegex(Regex::new(&entry.data?).ok()?),
                EntryKind::AllowA | EntryKind::AllowAAAA => {
                    ListEntryKind::Hosts((entry.domain?.into_owned(), entry.data?.parse::<IpAddr>().ok()?))
                }
            })
        }))
    }
}
