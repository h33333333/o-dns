mod logging;
use cache::Cache;
pub use logging::setup_logging;
mod hosts;
pub use hosts::{Denylist, Hosts};
mod upstream;
pub use upstream::resolve_with_upstream;
mod cache;
pub use cache::{CacheRecordKind, CachedRecord};
pub mod util;

use std::net::SocketAddr;
use tokio::sync::RwLock;

/// Recommended eDNS buf size
pub const DEFAULT_EDNS_BUF_CAPACITY: usize = 1232;
/// RFC1035
pub const MAX_STANDARD_DNS_MSG_SIZE: usize = 512;

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
