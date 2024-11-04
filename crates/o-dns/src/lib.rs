mod logging;
pub use logging::setup_logging;
mod hosts;
pub use hosts::{Denylist, Hosts};
mod cache;
use cache::Cache;
mod connection;
pub use connection::Connection;
mod resolver;
pub use resolver::Resolver;
pub mod util;

use std::net::SocketAddr;
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
    pub fn new() -> Self {
        State {
            upstream_resolver: "1.1.1.1:53".parse().expect("shouldn't have failed"),
            denylist: Default::default(),
            hosts: Default::default(),
            cache: Default::default(),
        }
    }
}
