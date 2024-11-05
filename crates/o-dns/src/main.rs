use anyhow::Context as _;
use o_dns::{setup_logging, DnsServer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging()?;

    let mut server = DnsServer::new()
        .await
        .context("failed to instantiate the DNS server")?;

    server.add_workers(5).await;

    server.block_until_completion().await
}
