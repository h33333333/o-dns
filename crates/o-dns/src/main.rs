use o_dns::{setup_logging, App};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging()?;

    App::run_until_completion().await
}
