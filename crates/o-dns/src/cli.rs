use std::net::IpAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(version, name = "o-dns")]
pub struct Args {
    #[arg(long, value_name = "PATH")]
    pub denylist_path: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub allowlist_path: Option<PathBuf>,
    #[arg( long, value_name = "CONNECTIONS", default_value_t = 5, value_parser = clap::value_parser!(u8).range(1..=10))]
    pub max_parallel_connections: u8,
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1")]
    pub host: IpAddr,
    #[arg(short('p'), long, value_name = "PORT", default_value_t = 53)]
    pub port: u16,
    #[arg(long, value_name = "ADDR", default_value = "1.1.1.1")]
    pub upstream_resolver: IpAddr,
    #[arg(long, value_name = "PORT", default_value_t = 53)]
    pub upstream_port: u16,
    #[arg(long, value_name = "PATH", default_value = "query_log.db")]
    pub query_log_path: PathBuf,
    #[arg(short('s'), long, default_value_t = false)]
    pub disable_api_server: bool,
    #[arg(long, value_name = "PORT", default_value_t = 3000)]
    pub api_server_port: u16,
}
