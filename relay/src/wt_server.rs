use crate::auth_proxy::{AuthProxy, SessionPrincipal, handle_http_proxy_io};
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use wtransport::endpoint::IncomingSession;
use wtransport::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run_wt_server(
    bind: SocketAddr,
    identity: wtransport::Identity,
    policy: SecurityPolicy,
    motd: Option<String>,
    auth_proxy: Option<Arc<AuthProxy>>,
    disable_raw_tcp: bool,
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
        let auth_proxy = auth_proxy.clone();
        tokio::spawn(async move {
            if let Err(err) =
                handle_incoming(incoming, policy, motd, auth_proxy, disable_raw_tcp).await
            {
                debug!(?err, "WebTransport session ended");
            }
        });
    }
}

async fn handle_incoming(
    incoming: IncomingSession,
    policy: SecurityPolicy,
    motd: Option<String>,
    auth_proxy: Option<Arc<AuthProxy>>,
    disable_raw_tcp: bool,
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
    run_wt_session(conn, policy, motd, http_token, auth_proxy, disable_raw_tcp).await
}

struct UdpFlow {
    socket: Arc<UdpSocket>,
    task: JoinHandle<()>,
}

async fn run_wt_session(
    conn: Connection,
    policy: SecurityPolicy,
    motd: Option<String>,
    http_token: Option<String>,
    auth_proxy: Option<Arc<AuthProxy>>,
    disable_raw_tcp: bool,
) -> Result<()> {
    // 1. Accept Control Stream (first bi-stream with kind == 0x00) with handshake timeout.
    let (mut ctrl_send, mut ctrl_recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.accept_bi())
        .await
        .context("WebTransport control stream accept timed out")??;
    let mut kind_buf = [0u8; 1];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, ctrl_recv.read_exact(&mut kind_buf))
        .await
        .context("WebTransport control stream kind read timed out")??;
    if kind_buf[0] != stream_kind::CONTROL {
        bail!("First WebTransport stream must be control (0x00), got 0x{:02x}", kind_buf[0]);
    }

    // 2. Read CLIENT_INFO frame.
    let (msg_type, payload) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, read_control_frame(&mut ctrl_recv))
            .await
            .context("WebTransport CLIENT_INFO read timed out")??;
    if msg_type != control_msg::INFO {
        bail!("Expected INFO (0x05) on control stream, got 0x{msg_type:02x}");
    }
    let client_info = decode_info(&payload)?;

    let info_token = extract_token_from_info(&client_info);
    if policy.requires_auth() && http_token.is_none() {
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
    let session_token = http_token.or(info_token);
    let principal = auth_proxy
        .as_ref()
        .map(|ap| Arc::new(ap.resolve_principal(session_token.as_deref(), disable_raw_tcp)));

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
    if let (Some(ap), Some(p)) = (&auth_proxy, &principal) {
        server_exts.push(Extension {
            id: ext_id::AUTH_PROXY,
            data: ap.advertised_extension_json(p),
        });
    }
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

    let stream_sem = Arc::new(Semaphore::new(policy.max_streams_per_session));
    let mut stream_limiter = policy.new_stream_limiter();
    let udp_flows: Arc<Mutex<HashMap<u32, UdpFlow>>> = Arc::new(Mutex::new(HashMap::new()));
    let tcp_tasks: Arc<Mutex<HashMap<u64, JoinHandle<()>>>> = Arc::new(Mutex::new(HashMap::new()));
    let next_tcp_id = Arc::new(AtomicU64::new(1));
    let ctrl_send = Arc::new(Mutex::new(ctrl_send));

    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Result<(u8, Vec<u8>)>>(32);
    let ctrl_reader_task = tokio::spawn(async move {
        loop {
            let res = read_control_frame(&mut ctrl_recv).await;
            let is_err = res.is_err();
            if ctrl_tx.send(res).await.is_err() || is_err {
                break;
            }
        }
    });

    // 4. Main session loop: accept TCP bi-streams, control frames, and UDP datagrams.
    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                let (send, recv) = bi?;
                let permit = if stream_limiter.allow() {
                    Arc::clone(&stream_sem).try_acquire_owned().ok()
                } else {
                    None
                };
                let Some(permit) = permit else {
                    let mut send = send;
                    let _ = send.write_all(&[close_reason::THROTTLED, 0x00]).await;
                    let _ = send.finish().await;
                    continue;
                };
                let policy = policy.clone();
                let auth_proxy_c = auth_proxy.clone();
                let principal_c = principal.clone();
                let tcp_id = next_tcp_id.fetch_add(1, Ordering::Relaxed);
                let tcp_tasks_ref = Arc::clone(&tcp_tasks);
                let handle = tokio::spawn(async move {
                    if let Err(err) = handle_tcp_stream(
                        send,
                        recv,
                        policy,
                        auth_proxy_c,
                        principal_c,
                        disable_raw_tcp,
                        permit,
                    )
                    .await
                    {
                        debug!(?err, "WT TCP stream closed");
                    }
                    tcp_tasks_ref.lock().await.remove(&tcp_id);
                });
                tcp_tasks.lock().await.insert(tcp_id, handle);
            }
            frame_opt = ctrl_rx.recv() => {
                let Some(frame) = frame_opt else {
                    break;
                };
                let (mtype, mpayload) = frame?;
                match mtype {
                    control_msg::UDP_BIND => {
                        if !stream_limiter.allow() {
                            if mpayload.len() >= 4 {
                                let flow_id = u32::from_le_bytes(mpayload[0..4].try_into().unwrap());
                                let ctrl_send = Arc::clone(&ctrl_send);
                                tokio::spawn(async move {
                                    let _ = send_udp_bound(&ctrl_send, flow_id, close_reason::THROTTLED).await;
                                });
                            }
                            continue;
                        }
                        let conn_c = conn.clone();
                        let ctrl_send_c = Arc::clone(&ctrl_send);
                        let udp_flows_c = Arc::clone(&udp_flows);
                        let policy_c = policy.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_udp_bind(
                                &conn_c,
                                &ctrl_send_c,
                                &udp_flows_c,
                                &policy_c,
                                &mpayload,
                            ).await {
                                debug!(?err, "UDP bind failed");
                            }
                        });
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

    ctrl_reader_task.abort();
    for (_, handle) in tcp_tasks.lock().await.drain() {
        handle.abort();
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

async fn handle_tcp_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    policy: SecurityPolicy,
    auth_proxy: Option<Arc<AuthProxy>>,
    principal: Option<Arc<SessionPrincipal>>,
    disable_raw_tcp: bool,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    let mut kind_buf = [0u8; 1];
    tokio::time::timeout(STREAM_HEADER_TIMEOUT, recv.read_exact(&mut kind_buf))
        .await
        .context("WT stream kind read timed out")??;

    if kind_buf[0] == stream_kind::HTTP_PROXY {
        let mut hdr = [0u8; 3];
        tokio::time::timeout(STREAM_HEADER_TIMEOUT, recv.read_exact(&mut hdr))
            .await
            .context("WT HTTP_PROXY header read timed out")??;
        let route_len = u16::from_le_bytes([hdr[1], hdr[2]]) as usize;
        if route_len == 0 || route_len > 1024 {
            let _ = send.write_all(&[close_reason::INVALID_INFO, 0x00]).await;
            let _ = send.finish().await;
            return Ok(());
        }
        let mut route_bytes = vec![0u8; route_len];
        tokio::time::timeout(STREAM_HEADER_TIMEOUT, recv.read_exact(&mut route_bytes))
            .await
            .context("WT HTTP_PROXY route read timed out")??;
        let Ok(route_id) = String::from_utf8(route_bytes) else {
            let _ = send.write_all(&[close_reason::INVALID_INFO, 0x00]).await;
            let _ = send.finish().await;
            return Ok(());
        };
        let (Some(ap), Some(p)) = (auth_proxy, principal) else {
            let _ = send.write_all(&[close_reason::BLOCKED, 0x00]).await;
            let _ = send.finish().await;
            return Ok(());
        };
        let Some(route) = ap.get_route(&route_id, &p) else {
            let reason = if p.allowed_routes.is_empty() && !ap.principals.is_empty() {
                close_reason::AUTH_REQUIRED
            } else {
                close_reason::BLOCKED
            };
            let _ = send.write_all(&[reason, 0x00]).await;
            let _ = send.finish().await;
            return Ok(());
        };
        send.write_all(&[0x00, 0x00]).await?;
        let io = tokio::io::join(recv, send);
        return handle_http_proxy_io(io, route, ap, policy).await;
    }

    if kind_buf[0] != stream_kind::TCP {
        let _ = send.write_all(&[close_reason::INVALID_INFO, 0x00]).await;
        let _ = send.finish().await;
        return Ok(());
    }

    let mut hdr_rest = [0u8; 5];
    tokio::time::timeout(STREAM_HEADER_TIMEOUT, recv.read_exact(&mut hdr_rest))
        .await
        .context("WT stream header read timed out")??;
    if disable_raw_tcp || principal.as_ref().is_some_and(|p| !p.allow_raw_tcp) {
        let _ = send.write_all(&[close_reason::BLOCKED, 0x00]).await;
        let _ = send.finish().await;
        return Ok(());
    }
    let port = u16::from_le_bytes([hdr_rest[1], hdr_rest[2]]);
    let host_len = u16::from_le_bytes([hdr_rest[3], hdr_rest[4]]) as usize;
    if host_len == 0 || host_len > 1024 {
        let _ = send.write_all(&[close_reason::INVALID_INFO, 0x00]).await;
        let _ = send.finish().await;
        return Ok(());
    }
    let mut host_bytes = vec![0u8; host_len];
    tokio::time::timeout(STREAM_HEADER_TIMEOUT, recv.read_exact(&mut host_bytes))
        .await
        .context("WT stream host read timed out")??;
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

    let should_reset = {
        tokio::pin!(c2s);
        tokio::pin!(s2c);
        tokio::select! {
            res = &mut c2s => {
                match res {
                    Ok(()) => {
                        s2c.await.is_err()
                    }
                    Err(_) => true,
                }
            }
            res = &mut s2c => {
                match res {
                    Ok(()) => {
                        c2s.await.is_err()
                    }
                    Err(_) => true,
                }
            }
        }
    };
    if should_reset {
        let _ = send.reset(0u32.into());
    }
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
    if flow_id >= (1 << 30) {
        send_udp_bound(ctrl_send, flow_id, close_reason::INVALID_INFO).await?;
        return Ok(());
    }
    if udp_flows.lock().await.len() >= policy.max_streams_per_session {
        send_udp_bound(ctrl_send, flow_id, close_reason::THROTTLED).await?;
        return Ok(());
    }
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
    let sock = match UdpSocket::bind(bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(_) => {
            send_udp_bound(ctrl_send, flow_id, close_reason::UNREACHABLE).await?;
            return Ok(());
        }
    };
    if sock.connect(target).await.is_err() {
        send_udp_bound(ctrl_send, flow_id, close_reason::UNREACHABLE).await?;
        return Ok(());
    }

    let sock_recv = Arc::clone(&sock);
    let conn_clone = conn.clone();
    let ctrl_send_exit = Arc::clone(ctrl_send);
    let udp_flows_exit = Arc::clone(udp_flows);
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut prefix = Vec::with_capacity(8);
        if encode_varint(flow_id as u64, &mut prefix).is_err() {
            return;
        }
        loop {
            match sock_recv.recv(&mut buf).await {
                Ok(n) => {
                    let mut pkt = Vec::with_capacity(prefix.len() + n);
                    pkt.extend_from_slice(&prefix);
                    pkt.extend_from_slice(&buf[..n]);
                    match conn_clone.send_datagram(pkt) {
                        Ok(()) => {}
                        Err(wtransport::error::SendDatagramError::TooLarge) => continue,
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }
        udp_flows_exit.lock().await.remove(&flow_id);
        let _ = ctrl_send_exit
            .lock()
            .await
            .write_all(&encode_control_frame(
                control_msg::UDP_CLOSE,
                &flow_id.to_le_bytes(),
            ))
            .await;
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
