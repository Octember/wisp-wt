use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "wisp-wt-relay",
    about = "Dual-stack WebTransport + WebSocket Wisp relay"
)]
pub struct RelayConfig {
    /// UDP bind address for HTTP/3 WebTransport
    #[arg(long, env = "WISP_WT_BIND", default_value = "127.0.0.1:4433")]
    pub wt_bind: SocketAddr,

    /// TCP bind address for WebSocket fallback
    #[arg(long, env = "WISP_WS_BIND", default_value = "127.0.0.1:4434")]
    pub ws_bind: SocketAddr,

    /// Enable TLS (wss://) on the WebSocket listener using the same cert/key
    #[arg(long, env = "WISP_WS_TLS", default_value_t = false)]
    pub ws_tls: bool,

    /// Optional dev HTTP endpoint serving GET /cert-hash JSON for local browser demos
    #[arg(long, env = "WISP_DEV_HTTP_BIND")]
    pub dev_http_bind: Option<SocketAddr>,

    /// Path to PEM certificate chain (required unless --self-signed is set)
    #[arg(long, env = "WISP_CERT")]
    pub cert: Option<PathBuf>,

    /// Path to PEM private key (required unless --self-signed is set)
    #[arg(long, env = "WISP_KEY")]
    pub key: Option<PathBuf>,

    /// Generate an ephemeral ECDSA P-256 <=14-day self-signed cert for local dev
    #[arg(long, env = "WISP_SELF_SIGNED", default_value_t = false)]
    pub self_signed: bool,

    /// Additional SANs for --self-signed (localhost and 127.0.0.1 are always included)
    #[arg(long = "cert-san")]
    pub cert_sans: Vec<String>,

    /// Allowed Origin headers (exact or wildcard host prefix like https://*.trynix.dev)
    #[arg(
        long = "allow-origin",
        env = "WISP_ALLOW_ORIGINS",
        value_delimiter = ','
    )]
    pub allow_origins: Vec<String>,

    /// Allow any Origin (for local development only)
    #[arg(long, env = "WISP_ALLOW_ANY_ORIGIN", default_value_t = false)]
    pub allow_any_origin: bool,

    /// Optional bearer/password auth token
    #[arg(long, env = "WISP_AUTH_TOKEN")]
    pub auth_token: Option<String>,

    /// Allow outbound connections to loopback/private/link-local IPs (default false for SSRF safety)
    #[arg(long, env = "WISP_ALLOW_LOOPBACK", default_value_t = false)]
    pub allow_loopback: bool,

    /// Explicitly blocked destination hostnames (comma-separated or repeatable)
    #[arg(long = "block-host", value_delimiter = ',')]
    pub block_hosts: Vec<String>,

    /// Optional allow-list of destination hostnames
    #[arg(long = "allow-host", value_delimiter = ',')]
    pub allow_hosts: Vec<String>,

    /// Maximum concurrent sessions per client IP
    #[arg(long, default_value_t = 16)]
    pub max_sessions_per_ip: usize,

    /// Maximum concurrent streams per session
    #[arg(long, default_value_t = 256)]
    pub max_streams_per_session: usize,

    /// Stream creation rate limit per second per session
    #[arg(long, default_value_t = 64.0)]
    pub streams_per_sec: f64,

    /// Stream creation burst per session
    #[arg(long, default_value_t = 128.0)]
    pub streams_burst: f64,

    /// Session creation rate limit per second per IP
    #[arg(long, default_value_t = 8.0)]
    pub sessions_per_sec: f64,

    /// Session creation burst per IP
    #[arg(long, default_value_t = 16.0)]
    pub sessions_burst: f64,

    /// Optional Message of the Day sent in Wisp v2 INFO extension 0x04
    #[arg(long, env = "WISP_MOTD")]
    pub motd: Option<String>,

    /// Path to JSON config for opt-in secretless / capability-gated HTTP auth proxy
    #[arg(long, env = "WISP_AUTH_PROXY_CONFIG")]
    pub auth_proxy_config: Option<PathBuf>,

    /// Disable raw TCP (0x01) streams when operating as an auth-proxy-only relay
    #[arg(long, env = "WISP_DISABLE_RAW_TCP", default_value_t = false)]
    pub disable_raw_tcp: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            wt_bind: "127.0.0.1:4433".parse().unwrap(),
            ws_bind: "127.0.0.1:4434".parse().unwrap(),
            ws_tls: false,
            dev_http_bind: None,
            cert: None,
            key: None,
            self_signed: true,
            cert_sans: Vec::new(),
            allow_origins: Vec::new(),
            allow_any_origin: false,
            auth_token: None,
            allow_loopback: false,
            block_hosts: Vec::new(),
            allow_hosts: Vec::new(),
            max_sessions_per_ip: 16,
            max_streams_per_session: 256,
            streams_per_sec: 64.0,
            streams_burst: 128.0,
            sessions_per_sec: 8.0,
            sessions_burst: 16.0,
            motd: None,
            auth_proxy_config: None,
            disable_raw_tcp: false,
        }
    }
}
