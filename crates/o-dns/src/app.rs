use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::Context as _;
use o_dns_api::ApiServer;
use o_dns_common::{AccessListEntryKind, DnsServerCommand};
use o_dns_db::{EntryKind, ListEntry, SqliteDb};
use regex::Regex;
use sqlx::SqliteConnection;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinSet;

use crate::access_lists::{parse_denylist_file, parse_hosts_file};
use crate::query_logger::QueryLogger;
use crate::util::{hash_to_u128, read_checksum, write_to_file};
use crate::{Args, DnsServer};

pub struct App;

impl App {
    pub async fn run_until_completion(args: Args, config_path: PathBuf) -> anyhow::Result<()> {
        let dns_bind_addr = SocketAddr::new(args.host, args.port);
        let upstream_resolver_addr = SocketAddr::new(args.upstream_resolver, args.upstream_port);

        // Channel for query logs
        let (log_tx, log_rx) = unbounded_channel();

        let sqlite_db = SqliteDb::new(&config_path)
            .await
            .context("failed to establish an SQLite DB connection")?;

        sqlite_db
            .init_tables()
            .await
            .context("failed to initialize DB tables")?;

        // Populate the hosts and denylist tables
        let mut txn = sqlite_db.begin_transaction().await?;
        if let Some(path) = args.denylist_path.as_ref() {
            let checksum_path = &config_path.join("denylist_checksum");
            // Read the previous checksum (if present)
            let checksum = read_checksum(&checksum_path)
                .await
                .context("failed to read denylist checksum")?;

            if let Some(updated_checksum) = parse_denylist_file(path, &mut txn, checksum)
                .await
                .context("error while parsing the denylist file")?
            {
                write_to_file(&checksum_path, &updated_checksum)
                    .await
                    .context("failed to write the updated denylist checksum")?;
            }
        }
        if let Some(path) = args.allowlist_path.as_ref() {
            let checksum_path = &config_path.join("hosts_checksum");
            // Read the previous checksum (if present)
            let checksum = read_checksum(&checksum_path)
                .await
                .context("failed to read hosts checksum")?;

            if let Some(updated_checksum) = parse_hosts_file(path, &mut txn, checksum)
                .await
                .context("error while parsing the hosts file")?
            {
                write_to_file(&checksum_path, &updated_checksum)
                    .await
                    .context("failed to write the updated hosts checksum")?;
            };
        }
        txn.commit()
            .await
            .context("failed to commit entries from denylist and hosts files")?;

        let query_logger = QueryLogger::new(log_rx, sqlite_db.clone())
            .await
            .context("error while creating a query logger")?;

        let (command_tx, command_rx) = tokio::sync::mpsc::channel(10);
        let mut server = DnsServer::new(dns_bind_addr, upstream_resolver_addr, log_tx, command_rx)
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
        server.add_workers(args.max_parallel_connections).await;
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
    ) -> anyhow::Result<impl Iterator<Item = AccessListEntryKind>> {
        let dynamic_entries = ListEntry::select_all(connection).await?;

        Ok(dynamic_entries.into_iter().filter_map(|entry| {
            let domain = entry.domain.map(|domain| hash_to_u128(domain.as_ref(), None));
            Some(match entry.kind {
                EntryKind::Deny => AccessListEntryKind::DenyDomain(domain?),
                EntryKind::DenyRegex => {
                    AccessListEntryKind::DenyRegex((entry.id, Some(Regex::new(&entry.data?).ok()?)))
                }
                EntryKind::AllowA | EntryKind::AllowAAAA => {
                    AccessListEntryKind::Hosts((domain?, entry.data?.parse::<IpAddr>().ok()?))
                }
            })
        }))
    }
}
