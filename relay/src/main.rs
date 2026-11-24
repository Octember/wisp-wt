use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;
use wisp_wt_relay::config::RelayConfig;
use wisp_wt_relay::run_relay;

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cfg = RelayConfig::parse();
    tokio::select! {
        res = run_relay(cfg) => res,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutting down relay");
            Ok(())
        }
    }
}
