use crate::config::RelayConfig;
use crate::protocol::close_reason;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket, lookup_host};

#[derive(Clone)]
pub struct SecurityPolicy {
    inner: Arc<SecurityPolicyInner>,
    limiter: Arc<Mutex<RateLimiterState>>,
}

pub struct SecurityPolicyInner {
    pub allow_origins: Vec<String>,
    pub allow_any_origin: bool,
    pub auth_token: Option<String>,
    pub allow_loopback: bool,
    pub block_hosts: Vec<String>,
    pub allow_hosts: Vec<String>,
    pub max_sessions_per_ip: usize,
    pub max_streams_per_session: usize,
    pub streams_per_sec: f64,
    pub streams_burst: f64,
    pub sessions_per_sec: f64,
    pub sessions_burst: f64,
}

impl Deref for SecurityPolicy {
    type Target = SecurityPolicyInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

struct TokenBucket {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    fn try_consume(&mut self, rate: f64, burst: f64, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct RateLimiterState {
    session_counts: HashMap<IpAddr, usize>,
    session_buckets: HashMap<IpAddr, TokenBucket>,
}

pub struct SessionPermit {
    ip: IpAddr,
    limiter: Arc<Mutex<RateLimiterState>>,
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.limiter.lock()
            && let Some(count) = guard.session_counts.get_mut(&self.ip)
        {
            if *count <= 1 {
                guard.session_counts.remove(&self.ip);
            } else {
                *count -= 1;
            }
        }
    }
}

pub struct StreamRateLimiter {
    bucket: TokenBucket,
    rate: f64,
    burst: f64,
}

impl StreamRateLimiter {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            bucket: TokenBucket::new(burst, Instant::now()),
            rate,
            burst,
        }
    }

    pub fn allow(&mut self) -> bool {
        self.bucket
            .try_consume(self.rate, self.burst, Instant::now())
    }
}

impl SecurityPolicy {
    pub fn from_config(cfg: &RelayConfig) -> Self {
        Self {
            inner: Arc::new(SecurityPolicyInner {
                allow_origins: cfg
                    .allow_origins
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                allow_any_origin: cfg.allow_any_origin,
                auth_token: cfg.auth_token.clone(),
                allow_loopback: cfg.allow_loopback,
                block_hosts: cfg
                    .block_hosts
                    .iter()
                    .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                    .collect(),
                allow_hosts: cfg
                    .allow_hosts
                    .iter()
                    .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                    .collect(),
                max_sessions_per_ip: cfg.max_sessions_per_ip,
                max_streams_per_session: cfg.max_streams_per_session,
                streams_per_sec: cfg.streams_per_sec,
                streams_burst: cfg.streams_burst,
                sessions_per_sec: cfg.sessions_per_sec,
                sessions_burst: cfg.sessions_burst,
            }),
            limiter: Arc::new(Mutex::new(RateLimiterState {
                session_counts: HashMap::new(),
                session_buckets: HashMap::new(),
            })),
        }
    }

    pub fn check_origin(&self, origin: Option<&str>) -> bool {
        if self.allow_any_origin {
            return true;
        }
        let Some(origin) = origin else {
            return false;
        };
        let origin_lower = origin.to_ascii_lowercase();
        for a in &self.allow_origins {
            if a == &origin_lower {
                return true;
            }
            if let Some((scheme, rest)) = a.split_once("://*.") {
                if rest.is_empty()
                    || rest.contains(['@', '/', '?', '#', '*'])
                    || rest.split('.').any(|l| l.is_empty())
                {
                    continue;
                }
                if let Some((o_scheme, o_host)) = origin_lower.split_once("://") {
                    if o_host.is_empty()
                        || o_host.contains(['@', '/', '?', '#'])
                        || o_host.split('.').any(|l| l.is_empty())
                    {
                        continue;
                    }
                    let suffix = format!(".{rest}");
                    if scheme == o_scheme
                        && let Some(sub) = o_host.strip_suffix(&suffix)
                        && !sub.is_empty()
                        && !sub.contains(':')
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn verify_token(&self, candidate: Option<&str>) -> bool {
        let Some(expected) = &self.auth_token else {
            return true;
        };
        let Some(actual) = candidate else {
            return false;
        };
        ct_eq(expected.as_bytes(), actual.as_bytes())
    }

    pub fn requires_auth(&self) -> bool {
        self.auth_token.is_some()
    }

    pub fn try_acquire_session(&self, ip: IpAddr) -> Option<SessionPermit> {
        let mut guard = self.limiter.lock().ok()?;
        let now = Instant::now();
        if guard.session_buckets.len() > 1024 {
            let stale_after = Duration::from_secs(300);
            let RateLimiterState {
                session_counts,
                session_buckets,
            } = &mut *guard;
            session_buckets.retain(|k, b| {
                session_counts.contains_key(k) || now.duration_since(b.last) <= stale_after
            });
        }
        let active = guard.session_counts.get(&ip).copied().unwrap_or(0);
        if active >= self.max_sessions_per_ip {
            return None;
        }
        let burst = self.sessions_burst;
        let rate = self.sessions_per_sec;
        let bucket = guard
            .session_buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(burst, now));
        if !bucket.try_consume(rate, burst, now) {
            return None;
        }
        guard.session_counts.insert(ip, active + 1);
        Some(SessionPermit {
            ip,
            limiter: Arc::clone(&self.limiter),
        })
    }

    pub fn new_stream_limiter(&self) -> StreamRateLimiter {
        StreamRateLimiter::new(self.streams_per_sec, self.streams_burst)
    }
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn extract_query_token(path_and_query: &str) -> Option<String> {
    let (_, query) = path_and_query.split_once('?')?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == "token"
            && !v.is_empty()
        {
            return Some(v.to_string());
        }
    }
    None
}

pub fn extract_bearer_header(header_val: &str) -> Option<&str> {
    let (scheme, rest) = header_val.split_once(' ')?;
    if !matches!(scheme, "Bearer" | "bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

pub fn extract_http_token(path_and_query: &str, auth_header: Option<&str>) -> Option<String> {
    extract_query_token(path_and_query).or_else(|| {
        auth_header
            .and_then(extract_bearer_header)
            .map(str::to_string)
    })
}

fn host_matches(host: &str, pattern: &str) -> bool {
    host == pattern
        || host
            .strip_suffix(pattern)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

pub async fn connect_tcp(
    host: &str,
    port: u16,
    policy: &SecurityPolicy,
    timeout: Duration,
) -> std::result::Result<TcpStream, u8> {
    let addrs = resolve_and_check_target(host, port, policy).await?;
    let mut last_err = close_reason::UNREACHABLE;
    for addr in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                last_err = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    close_reason::CONNECTION_REFUSED
                } else {
                    close_reason::UNREACHABLE
                };
            }
            Err(_) => {
                last_err = close_reason::CONNECT_TIMEOUT;
            }
        }
    }
    Err(last_err)
}

pub async fn connect_udp(
    host: &str,
    port: u16,
    policy: &SecurityPolicy,
) -> std::result::Result<UdpSocket, u8> {
    let addrs = resolve_and_check_target(host, port, policy).await?;
    let mut last_err = close_reason::UNREACHABLE;
    for addr in addrs {
        let bind_addr: SocketAddr = if addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        if let Ok(sock) = UdpSocket::bind(bind_addr).await {
            if sock.connect(addr).await.is_ok() {
                return Ok(sock);
            }
            last_err = close_reason::UNREACHABLE;
        }
    }
    Err(last_err)
}

pub async fn resolve_and_check_target(
    host: &str,
    port: u16,
    policy: &SecurityPolicy,
) -> std::result::Result<Vec<SocketAddr>, u8> {
    if host.is_empty() || port == 0 {
        return Err(close_reason::INVALID_INFO);
    }

    let host_lower = host.trim_end_matches('.').to_ascii_lowercase();
    if host_lower.is_empty() {
        return Err(close_reason::INVALID_INFO);
    }
    if policy
        .block_hosts
        .iter()
        .any(|b| host_matches(&host_lower, b))
    {
        return Err(close_reason::BLOCKED);
    }
    if !policy.allow_hosts.is_empty()
        && !policy
            .allow_hosts
            .iter()
            .any(|a| host_matches(&host_lower, a))
    {
        return Err(close_reason::BLOCKED);
    }

    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(std::time::Duration::from_secs(5), lookup_host((host, port)))
            .await
            .map_err(|_| close_reason::UNREACHABLE)?
            .map_err(|_| close_reason::UNREACHABLE)?
            .collect();

    if addrs.is_empty() {
        return Err(close_reason::UNREACHABLE);
    }

    if !policy.allow_loopback {
        for addr in &addrs {
            if is_disallowed_ip(addr.ip()) {
                return Err(close_reason::BLOCKED);
            }
        }
    }

    Ok(addrs)
}

pub fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_disallowed_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_disallowed_v4(mapped);
            }
            is_disallowed_v6(v6)
        }
    }
}

fn is_disallowed_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || octets[0] == 0 // 0.0.0.0/8
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64) // CGNAT 100.64.0.0/10
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // 192.0.0.0/24
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) // 192.0.2.0/24 (TEST-NET-1)
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18) // 198.18.0.0/15 (Benchmarking)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) // 198.51.100.0/24 (TEST-NET-2)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113) // 203.0.113.0/24 (TEST-NET-3)
        || (octets[0] & 0xf0) == 240 // 240.0.0.0/4 (Reserved)
}

fn is_disallowed_v6(ip: Ipv6Addr) -> bool {
    let segs = ip.segments();
    ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || (segs[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
        || (segs[0] & 0xffc0) == 0xfe80 // Link-local fe80::/10
        || (segs[0] & 0xffc0) == 0xfec0 // Site-local fec0::/10
        || matches!(
            segs,
            [0, 0, 0, 0, 0, 0, ..] // ::/96
                | [0x0064, 0xff9b, 0, 0, 0, 0, ..] // 64:ff9b::/96
                | [0x0064, 0xff9b, 0x0001, ..] // 64:ff9b:1::/48
                | [0x2002, ..] // 2002::/16 (6to4)
                | [0x2001, 0, ..] // 2001::/32 (Teredo)
                | [0x2001, 0x0db8, ..] // 2001:db8::/32 (Documentation)
        )
}
