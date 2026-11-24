use crate::protocol::{
    Extension, InfoPayload, close_reason, control_msg, decode_info, decode_varint,
    encode_control_frame, encode_info, encode_varint, ext_id, extract_token_from_info,
    stream_kind,
};
use crate::security::{
    SecurityPolicy, extract_bearer_header, extract_query_token, resolve_and_check_target,
};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use wtransport::endpoint::IncomingSession;
use wtransport::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run_wt_server(
    bind: SocketAddr,
    identity: wtransport::Identity,
    policy: SecurityPolicy,
    motd: Option<String>,
) -> Result<()> {
    let config = ServerConfig::builder()
        .with_bind_address(bind)
        .with_identity(identity)
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .build();

    let server = Endpoint::server(config).context("Start WebTransport server")?;
    let local_addr = server.local_addr()?;
    info!(%local_addr, "WebTransport (HTTP/3) relay listening");

    loop {
        let incoming = server.accept().await;
        let policy = policy.clone();
        let motd = motd.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_incoming(incoming, policy, motd).await {
                debug!(?err, "WebTransport session ended");
            }
        });
    }
}

async fn handle_incoming(
    incoming: IncomingSession,
    policy: SecurityPolicy,
    motd: Option<String>,
) -> Result<()> {
    let req = incoming.await?;
    let remote_ip = req.remote_address().ip();
    let origin = req.origin().map(str::to_string);

    if !policy.check_origin(origin.as_deref()) {
        warn!(?origin, %remote_ip, "Rejected WebTransport session: disallowed Origin");
        req.forbidden().await;
        return Ok(());
    }

    let Some(_permit) = policy.try_acquire_session(remote_ip) else {
        warn!(%remote_ip, "Rejected WebTransport session: rate limit");
        req.forbidden().await;
        return Ok(());
    };

    let http_token = extract_query_token(req.path()).or_else(|| {
        req.headers()
            .get("authorization")
            .and_then(|v| extract_bearer_header(v))
            .map(str::to_string)
    });

    if http_token.is_some() && !policy.verify_token(http_token.as_deref()) {
        warn!(%remote_ip, "Rejected WebTransport session: invalid HTTP token");
        req.forbidden().await;
        return Ok(());
    }

    let conn = req.accept().await?;
    run_wt_session(conn, policy, motd, http_token.is_some()).await
}

struct UdpFlow {
    socket: Arc<UdpSocket>,
    task: JoinHandle<()>,
}

async fn run_wt_session(
    conn: Connection,
    policy: SecurityPolicy,
    motd: Option<String>,
    http_authed: bool,
) -> Result<()> {
    // 1. Accept Control Stream (first bi-stream with kind == 0x00).
    let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;
    let mut kind_buf = [0u8; 1];
    ctrl_recv.read_exact(&mut kind_buf).await?;
    if kind_buf[0] != stream_kind::CONTROL {
        bail!("First WebTransport stream must be control (0x00), got 0x{:02x}", kind_buf[0]);
    }

    // 2. Read CLIENT_INFO frame.
    let (msg_type, payload) = read_control_frame(&mut ctrl_recv).await?;
    if msg_type != control_msg::INFO {
        bail!("Expected INFO (0x05) on control stream, got 0x{msg_type:02x}");
    }
    let client_info = decode_info(&payload)?;

    if policy.requires_auth() && !http_authed {
        let info_token = extract_token_from_info(&client_info);
        if info_token.is_none() {
            let _ = ctrl_send
                .write_all(&encode_control_frame(
                    control_msg::CLOSE,
                    &[close_reason::AUTH_REQUIRED],
                ))
                .await;
            let _ = ctrl_send.finish().await;
            bail!("Authentication required");
        }
        if !policy.verify_token(info_token.as_deref()) {
            let _ = ctrl_send
                .write_all(&encode_control_frame(
                    control_msg::CLOSE,
                    &[close_reason::AUTH_INVALID_PASSWORD],
                ))
                .await;
            let _ = ctrl_send.finish().await;
            bail!("Invalid authentication token");
        }
    }

    // 3. Send SERVER_INFO + READY.
    let mut server_exts = vec![
        Extension {
            id: ext_id::UDP,
            data: Vec::new(),
        },
        Extension {
            id: ext_id::STREAM_OPEN_CONFIRM,
            data: Vec::new(),
        },
    ];
    if let Some(m) = motd {
        server_exts.push(Extension {
            id: ext_id::MOTD,
            data: m.into_bytes(),
        });
    }
    let server_info = encode_info(&InfoPayload {
        major: 2,
        minor: 1,
        extensions: server_exts,
    });
    ctrl_send
        .write_all(&encode_control_frame(control_msg::INFO, &server_info))
        .await?;

    let max_dgram = conn.max_datagram_size().unwrap_or(1200).min(u16::MAX as usize) as u16;
    let mut ready_payload = Vec::with_capacity(6);
    ready_payload.extend_from_slice(&(policy.max_streams_per_session as u32).to_le_bytes());
    ready_payload.extend_from_slice(&max_dgram.to_le_bytes());
    ctrl_send
        .write_all(&encode_control_frame(control_msg::READY, &ready_payload))
        .await?;

    let active_streams = Arc::new(AtomicUsize::new(0));
    let mut stream_limiter = policy.new_stream_limiter();
    let udp_flows: Arc<Mutex<HashMap<u32, UdpFlow>>> = Arc::new(Mutex::new(HashMap::new()));
    let ctrl_send = Arc::new(Mutex::new(ctrl_send));

    // 4. Main session loop: accept TCP bi-streams, control frames, and UDP datagrams.
    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                let (send, recv) = bi?;
                if !stream_limiter.allow()
                    || active_streams.load(Ordering::Relaxed) >= policy.max_streams_per_session
                {
                    let mut send = send;
                    let _ = send.write_all(&[close_reason::THROTTLED, 0x00]).await;
                    let _ = send.finish().await;
                    continue;
                }
                let policy = policy.clone();
                let active = Arc::clone(&active_streams);
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_stream(send, recv, policy, active).await {
                        debug!(?err, "WT TCP stream closed");
                    }
                });
            }
            frame = read_control_frame(&mut ctrl_recv) => {
                let (mtype, mpayload) = frame?;
                match mtype {
                    control_msg::UDP_BIND => {
                        handle_udp_bind(
                            &conn,
                            &ctrl_send,
                            &udp_flows,
                            &policy,
                            &mpayload,
                        ).await?;
                    }
                    control_msg::UDP_CLOSE => {
                        if mpayload.len() >= 4 {
                            let flow_id = u32::from_le_bytes(mpayload[0..4].try_into().unwrap());
                            if let Some(flow) = udp_flows.lock().await.remove(&flow_id) {
                                flow.task.abort();
                            }
                        }
                    }
                    control_msg::CLOSE => {
                        break;
                    }
                    _ => {}
                }
            }
            dgram = conn.receive_datagram() => {
                let dgram = dgram?;
                if let Ok((flow_id_u64, prefix_len)) = decode_varint(&dgram) {
                    let flow_id = flow_id_u64 as u32;
                    let payload = &dgram[prefix_len..];
                    let sock_opt = udp_flows.lock().await.get(&flow_id).map(|f| Arc::clone(&f.socket));
                    if let Some(sock) = sock_opt {
                        let _ = sock.send(payload).await;
                    }
                }
            }
        }
    }

    for (_, flow) in udp_flows.lock().await.drain() {
        flow.task.abort();
    }
    Ok(())
}

async fn read_control_frame(recv: &mut RecvStream) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    recv.read_exact(&mut hdr).await?;
    let msg_type = hdr[0];
    let len = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
    if len > 64 * 1024 {
        bail!("Control frame too large: {len}");
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        recv.read_exact(&mut payload).await?;
    }
    Ok((msg_type, payload))
}

struct StreamGuard(Arc<AtomicUsize>);
impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn handle_tcp_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    policy: SecurityPolicy,
    active_streams: Arc<AtomicUsize>,
) -> Result<()> {
    active_streams.fetch_add(1, Ordering::Relaxed);
    let _guard = StreamGuard(active_streams);

    let mut hdr = [0u8; 6];
    recv.read_exact(&mut hdr).await?;
    if hdr[0] != stream_kind::TCP {
        let _ = send.write_all(&[close_reason::INVALID_INFO, 0x00]).await;
        let _ = send.finish().await;
        return Ok(());
    }
    let port = u16::from_le_bytes([hdr[2], hdr[3]]);
    let host_len = u16::from_le_bytes([hdr[4], hdr[5]]) as usize;
    if host_len == 0 || host_len > 1024 {
        let _ = send.write_all(&[close_reason::INVALID_INFO, 0x00]).await;
        let _ = send.finish().await;
        return Ok(());
    }
    let mut host_bytes = vec![0u8; host_len];
    recv.read_exact(&mut host_bytes).await?;
    let host = match String::from_utf8(host_bytes) {
        Ok(h) => h,
        Err(_) => {
            let _ = send.write_all(&[close_reason::INVALID_INFO, 0x00]).await;
            let _ = send.finish().await;
            return Ok(());
        }
    };

    let addrs = match resolve_and_check_target(&host, port, &policy).await {
        Ok(a) => a,
        Err(reason) => {
            let _ = send.write_all(&[reason, 0x00]).await;
            let _ = send.finish().await;
            return Ok(());
        }
    };

    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addrs[..])).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let reason = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => close_reason::CONNECTION_REFUSED,
                std::io::ErrorKind::TimedOut => close_reason::CONNECT_TIMEOUT,
                _ => close_reason::UNREACHABLE,
            };
            let _ = send.write_all(&[reason, 0x00]).await;
            let _ = send.finish().await;
            return Ok(());
        }
        Err(_) => {
            let _ = send.write_all(&[close_reason::CONNECT_TIMEOUT, 0x00]).await;
            let _ = send.finish().await;
            return Ok(());
        }
    };

    let _ = tcp.set_nodelay(true);
    send.write_all(&[0x00, 0x00]).await?;

    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let c2s = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match recv.read(&mut buf).await? {
                Some(0) | None => {
                    let _ = tcp_write.shutdown().await;
                    break;
                }
                Some(n) => {
                    tcp_write.write_all(&buf[..n]).await?;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let s2c = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = tcp_read.read(&mut buf).await?;
            if n == 0 {
                let _ = send.finish().await;
                break;
            }
            send.write_all(&buf[..n]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let _ = tokio::join!(c2s, s2c);
    Ok(())
}

async fn handle_udp_bind(
    conn: &Connection,
    ctrl_send: &Arc<Mutex<SendStream>>,
    udp_flows: &Arc<Mutex<HashMap<u32, UdpFlow>>>,
    policy: &SecurityPolicy,
    payload: &[u8],
) -> Result<()> {
    if payload.len() < 8 {
        return Ok(());
    }
    let flow_id = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let port = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    let host_len = u16::from_le_bytes(payload[6..8].try_into().unwrap()) as usize;
    if payload.len() < 8 + host_len {
        send_udp_bound(ctrl_send, flow_id, close_reason::INVALID_INFO).await?;
        return Ok(());
    }
    let Ok(host) = std::str::from_utf8(&payload[8..8 + host_len]) else {
        send_udp_bound(ctrl_send, flow_id, close_reason::INVALID_INFO).await?;
        return Ok(());
    };

    let addrs = match resolve_and_check_target(host, port, policy).await {
        Ok(a) => a,
        Err(reason) => {
            send_udp_bound(ctrl_send, flow_id, reason).await?;
            return Ok(());
        }
    };

    let target = addrs[0];
    let bind_addr: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = Arc::new(UdpSocket::bind(bind_addr).await?);
    sock.connect(target).await?;

    let sock_recv = Arc::clone(&sock);
    let conn_clone = conn.clone();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut prefix = Vec::with_capacity(8);
        let _ = encode_varint(flow_id as u64, &mut prefix);
        loop {
            match sock_recv.recv(&mut buf).await {
                Ok(n) => {
                    let mut pkt = Vec::with_capacity(prefix.len() + n);
                    pkt.extend_from_slice(&prefix);
                    pkt.extend_from_slice(&buf[..n]);
                    if conn_clone.send_datagram(pkt).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    if let Some(old) = udp_flows.lock().await.insert(flow_id, UdpFlow { socket: sock, task }) {
        old.task.abort();
    }
    send_udp_bound(ctrl_send, flow_id, 0x00).await?;
    Ok(())
}

async fn send_udp_bound(
    ctrl_send: &Arc<Mutex<SendStream>>,
    flow_id: u32,
    status: u8,
) -> Result<()> {
    let mut payload = [0u8; 5];
    payload[0..4].copy_from_slice(&flow_id.to_le_bytes());
    payload[4] = status;
    ctrl_send
        .lock()
        .await
        .write_all(&encode_control_frame(control_msg::UDP_BOUND, &payload))
        .await?;
    Ok(())
}
