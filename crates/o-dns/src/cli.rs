use std::{net::IpAddr, path::PathBuf};

use clap::Parser;

#[derive(Parser)]
#[command(version, name = "o-dns")]
pub struct Args {
    #[arg(short('d'), long, value_name = "PATH")]
    pub denylist_path: Option<PathBuf>,
    #[arg(short('a'), long, value_name = "PATH")]
    pub allowlist_path: Option<PathBuf>,
    #[arg(short('c'), long, value_name = "CONNECTIONS", default_value_t = 5, value_parser = clap::value_parser!(u8).range(1..=10))]
    pub max_parallel_connections: u8,
    #[arg(short('h'), long, value_name = "ADDR", default_value = "127.0.0.1")]
    pub host: IpAddr,
    #[arg(short('p'), long, value_name = "PORT", default_value_t = 53)]
    pub port: u16,
    #[arg(short('r'), long, value_name = "ADDR", default_value = "1.1.1.1")]
    pub upstream_resolver: IpAddr,
    #[arg(long, value_name = "PORT", default_value_t = 53)]
    pub upstream_port: u16,
}
