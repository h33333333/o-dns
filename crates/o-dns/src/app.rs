use std::net::SocketAddr;

use anyhow::Context as _;
use clap::Parser as _;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinSet;

use crate::api::ApiServer;
use crate::db::SqliteDb;
use crate::query_logger::QueryLogger;
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

        let query_logger = QueryLogger::new(log_rx, sqlite_db.clone())
            .await
            .context("error while creating a query logger")?;

        let server = DnsServer::new_with_workers(
            dns_bind_addr,
            upstream_resolver_addr,
            args.denylist_path.as_deref(),
            args.allowlist_path.as_deref(),
            log_tx,
            args.max_parallel_connections,
        )
        .await
        .context("failed to instantiate the DNS server")?;

        let mut tasks = JoinSet::new();
        tasks.spawn(server.block_until_completion());
        tasks.spawn(query_logger.watch_for_logs());
        if !args.disable_api_server {
            let api_server_bind_addr = SocketAddr::new(args.host, args.api_server_port);
            let api_server = ApiServer::new(sqlite_db);
            tasks.spawn(api_server.serve(api_server_bind_addr));
        }

        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result.context("failed to execute a task")? {
                tracing::debug!("Error: {:#}", e);
            }
        }

        Ok(())
    }
}
