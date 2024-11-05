use anyhow::Context;
use std::fs::File;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    filter::filter_fn, fmt::layer, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

pub const LOGGING_ENV: &'static str = "ODNS_LOG";
pub const LOGGING_FILE_ENV: &'static str = "ODNS_LOG_FILE";

pub fn setup_logging() -> anyhow::Result<()> {
    let log_file = File::options()
        .create(true)
        .append(true)
        .open("debug.log")
        .context("failed to create a log file")?;

    tracing_subscriber::registry()
        .with(
            layer()
                .with_filter(LevelFilter::INFO)
                .and_then(
                    layer()
                        .with_line_number(true)
                        .with_file(true)
                        .with_filter(filter_fn(|metadata| metadata.level() > &LevelFilter::INFO)),
                )
                .with_filter(
                    EnvFilter::builder()
                        .with_env_var(LOGGING_ENV)
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .with(
            layer()
                .pretty()
                .with_writer(log_file)
                .with_ansi(false)
                .with_filter(
                    EnvFilter::builder()
                        .with_env_var(LOGGING_FILE_ENV)
                        .with_default_directive(LevelFilter::TRACE.into())
                        .from_env_lossy(),
                ),
        )
        .try_init()
        .context("failed to initialize tracing_subscriber")
}
