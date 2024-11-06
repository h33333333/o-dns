use anyhow::Context as _;
use clap::Parser;
use o_dns::{setup_logging, Args, DnsServer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging()?;

    let args = Args::parse();

    let mut server = DnsServer::new_with_workers(&args)
        .await
        .context("failed to instantiate the DNS server")?;

    server.block_until_completion().await
}
