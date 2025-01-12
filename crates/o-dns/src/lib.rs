mod logging;
pub use logging::setup_logging;
mod access_lists;
pub use access_lists::{Denylist, Hosts};
mod cache;
mod connection;
pub use connection::Connection;
mod resolver;
pub use resolver::Resolver;
mod server;
pub use server::DnsServer;
mod cli;
pub use cli::Args;
mod app;
pub use app::App;
mod query_logger;
mod util;

use std::net::SocketAddr;

use cache::Cache;
use tokio::sync::RwLock;

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
    pub async fn new(upstream_resolver: SocketAddr) -> anyhow::Result<Self> {
        Ok(State {
            upstream_resolver,
            denylist: Default::default(),
            hosts: Default::default(),
            cache: Default::default(),
        })
    }
}
