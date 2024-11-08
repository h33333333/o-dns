mod logging;
pub use logging::setup_logging;
mod hosts;
pub use hosts::{Denylist, Hosts};
mod cache;
mod connection;
pub use connection::Connection;
mod resolver;
pub use resolver::Resolver;
mod server;
pub use server::DnsServer;
mod cli;
pub use cli::Args;
mod query_log;
mod util;

use anyhow::Context as _;
use cache::Cache;
use std::{net::SocketAddr, path::Path};
use tokio::sync::RwLock;
use util::{parse_denylist_file, parse_hosts_file};

/// Recommended eDNS buf size
pub const DEFAULT_EDNS_BUF_CAPACITY: usize = 1232;
/// RFC1035
pub const MAX_STANDARD_DNS_MSG_SIZE: usize = 512;
// EDNS DO BIT
pub const EDNS_DO_BIT: u32 = 1 << 15;

pub struct State {
    pub upstream_resolver: SocketAddr,
    pub denylist: RwLock<Denylist>,
    pub hosts: RwLock<Hosts>,
    pub cache: RwLock<Cache>,
}

impl State {
    pub async fn new(
        denylist_path: Option<&Path>,
        allowlist_path: Option<&Path>,
        upstream_resolver: SocketAddr,
    ) -> anyhow::Result<Self> {
        let mut denylist = Default::default();
        let mut allowlist = Default::default();

        // Populate the denylist
        if let Some(path) = denylist_path {
            parse_denylist_file(path, &mut denylist)
                .await
                .context("error while parsing the denylist file")?;
        }

        // Populate the hosts file
        if let Some(path) = allowlist_path {
            parse_hosts_file(path, &mut allowlist)
                .await
                .context("error while parsing the hosts file")?;
        }

        Ok(State {
            upstream_resolver,
            denylist: RwLock::new(denylist),
            hosts: RwLock::new(allowlist),
            cache: Default::default(),
        })
    }
}
