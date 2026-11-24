pub mod config;
pub mod protocol;
pub mod security;
pub mod tls;
pub mod ws_server;
pub mod wt_server;

use anyhow::Result;
use config::RelayConfig;
use security::SecurityPolicy;
use std::net::SocketAddr;
use tls::load_or_generate_tls;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;

pub async fn run_relay(cfg: RelayConfig) -> Result<()> {
    let tls = load_or_generate_tls(
        cfg.cert.as_deref(),
        cfg.key.as_deref(),
        cfg.self_signed,
        &cfg.cert_sans,
    )?;

    info!(
        sha256_base64 = %tls.cert_sha256_base64,
        sha256_hex = %tls.cert_sha256_hex,
        "Loaded relay TLS certificate"
    );

    let policy = SecurityPolicy::from_config(&cfg);
    let wt_fut = wt_server::run_wt_server(cfg.wt_bind, tls.identity, policy.clone(), cfg.motd.clone());
    let ws_tls = if cfg.ws_tls { Some(tls.rustls_config) } else { None };
    let ws_fut = ws_server::run_ws_server(cfg.ws_bind, ws_tls, policy, cfg.motd.clone());

    if let Some(dev_bind) = cfg.dev_http_bind {
        let dev_fut = run_dev_http_server(dev_bind, cfg.wt_bind, cfg.ws_bind, tls.cert_sha256_base64);
        tokio::select! {
            r = wt_fut => r?,
            r = ws_fut => r?,
            r = dev_fut => r?,
        }
    } else {
        tokio::select! {
            r = wt_fut => r?,
            r = ws_fut => r?,
        }
    }
    Ok(())
}

async fn run_dev_http_server(
    bind: SocketAddr,
    wt_bind: SocketAddr,
    ws_bind: SocketAddr,
    sha256_base64: String,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(%bind, "Dev /cert-hash HTTP server listening");

    let body = serde_json::json!({
        "sha256Base64": sha256_base64,
        "wtPort": wt_bind.port(),
        "wsPort": ws_bind.port(),
    })
    .to_string();

    loop {
        let (mut sock, _) = listener.accept().await?;
        let body = body.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}
