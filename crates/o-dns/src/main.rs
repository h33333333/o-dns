use anyhow::Context as _;
use clap::Parser as _;
use o_dns::{setup_logging, App, Args};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let config_path = args
        .config_path
        .as_ref()
        .and_then(|path| path.canonicalize().ok())
        .unwrap_or(dirs::home_dir().context("bug: no home dir")?.join(".odns"));
    // Ensure config directory exists
    tokio::fs::create_dir_all(&config_path)
        .await
        .context("failed to create the config directory")?;

    setup_logging(&config_path)?;

    App::run_until_completion(args, config_path).await
}
