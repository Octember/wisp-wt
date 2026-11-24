use crate::auth_proxy::{AuthProxy, handle_http_proxy_io};
use crate::protocol::{
    Extension, InfoPayload, close_reason, decode_info, encode_info, encode_ws_packet, ext_id,
    extract_token_from_info, ws_pkt, ws_stream_type,
};
use crate::security::{
    SecurityPolicy, extract_bearer_header, extract_query_token, resolve_and_check_target,
};
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{debug, info, warn};

const INITIAL_BUFFER: u32 = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run_ws_server(
    bind: SocketAddr,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    policy: SecurityPolicy,
    motd: Option<String>,
    auth_proxy: Option<Arc<AuthProxy>>,
    disable_raw_tcp: bool,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await.context("Bind WebSocket server")?;
    let local_addr = listener.local_addr()?;
    let tls_acceptor = tls_config.map(TlsAcceptor::from);
    info!(%local_addr, tls = tls_acceptor.is_some(), "WebSocket Wisp fallback relay listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let policy = policy.clone();
        let motd = motd.clone();
        let acceptor = tls_acceptor.clone();
        let auth_proxy = auth_proxy.clone();
        tokio::spawn(async move {
            let res = if let Some(acc) = acceptor {
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, acc.accept(stream)).await {
                    Ok(Ok(tls_stream)) => {
                        handle_ws_conn(tls_stream, peer, policy, motd, auth_proxy, disable_raw_tcp)
                            .await
                    }
                    Ok(Err(e)) => Err(e.into()),
                    Err(_) => Err(anyhow::anyhow!("WebSocket TLS handshake timed out")),
                }
            } else {
                handle_ws_conn(stream, peer, policy, motd, auth_proxy, disable_raw_tcp).await
            };
            if let Err(err) = res {
                debug!(?err, %peer, "WebSocket session ended");
            }
        });
    }
}

async fn finish_writer(out_tx: mpsc::Sender<Vec<u8>>, writer_task: JoinHandle<()>) {
    drop(out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer_task).await;
}

async fn handle_ws_conn<S>(
    stream: S,
    peer: SocketAddr,
    policy: SecurityPolicy,
    motd: Option<String>,
    auth_proxy: Option<Arc<AuthProxy>>,
    disable_raw_tcp: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(_permit) = policy.try_acquire_session(peer.ip()) else {
        return Ok(());
    };

    let mut is_v2 = false;
    let mut http_token: Option<String> = None;

    let mut ws_cfg = WebSocketConfig::default();
    ws_cfg.max_message_size = Some(16 * 1024 * 1024);
    ws_cfg.max_frame_size = Some(16 * 1024 * 1024);

    let ws = accept_hdr_async_with_config(
        stream,
        |req: &Request, mut resp: Response| {
            let origin = req.headers().get("origin").and_then(|v| v.to_str().ok());
            if !policy.check_origin(origin) {
                warn!(?origin, %peer, "Rejected WebSocket session: disallowed Origin");
                return Err(ErrorResponse::new(Some("Forbidden origin".into())));
            }

            let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
            let token = extract_query_token(path).or_else(|| {
                req.headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(extract_bearer_header)
                    .map(str::to_string)
            });
            if token.is_some() {
                if !policy.verify_token(token.as_deref()) {
                    return Err(ErrorResponse::new(Some("Unauthorized".into())));
                }
                http_token = token;
            }

            if let Some(proto) = req.headers().get("sec-websocket-protocol") {
                if let Ok(p) = proto.to_str() {
                    if p.split(',').map(str::trim).any(|s| s == "wisp-v2") {
                        is_v2 = true;
                        if let Ok(val) = "wisp-v2".parse() {
                            resp.headers_mut().insert("sec-websocket-protocol", val);
                        }
                    }
                }
            }
            Ok(resp)
        },
        Some(ws_cfg),
    )
    .await?;

    let (mut ws_sink, mut ws_stream) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(512);

    let writer_task = tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            if ws_sink.send(Message::Binary(pkt.into())).await.is_err() {
                break;
            }
        }
    });

    let mut session_token = http_token.clone();
    if is_v2 {
        let mut exts = vec![Extension {
            id: ext_id::UDP,
            data: Vec::new(),
        }];
        if let Some(ap) = &auth_proxy {
            let p = ap.resolve_principal(session_token.as_deref(), disable_raw_tcp);
            exts.push(Extension {
                id: ext_id::AUTH_PROXY,
                data: ap.advertised_extension_json(&p),
            });
        }
        if let Some(m) = motd {
            exts.push(Extension {
                id: ext_id::MOTD,
                data: m.into_bytes(),
            });
        }
        let info_bytes = encode_info(&InfoPayload {
            major: 2,
            minor: 1,
            extensions: exts,
        });
        let _ = out_tx.send(encode_ws_packet(ws_pkt::INFO, 0, &info_bytes)).await;

        // Wait for client INFO with timeout.
        let info_msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws_stream.next()).await;
        let Ok(Some(Ok(Message::Binary(first)))) = info_msg else {
            finish_writer(out_tx, writer_task).await;
            return Ok(());
        };
        if first.len() < 5 || first[0] != ws_pkt::INFO {
            let _ = out_tx
                .send(encode_ws_packet(ws_pkt::CLOSE, 0, &[close_reason::INVALID_INFO]))
                .await;
            finish_writer(out_tx, writer_task).await;
            return Ok(());
        }
        let client_info = decode_info(&first[5..])?;
        let info_tok = extract_token_from_info(&client_info);
        if policy.requires_auth() && session_token.is_none() {
            let reason = match info_tok {
                None => Some(close_reason::AUTH_REQUIRED),
                Some(ref t) if !policy.verify_token(Some(t.as_str())) => {
                    Some(close_reason::AUTH_INVALID_PASSWORD)
                }
                _ => None,
            };
            if let Some(r) = reason {
                let _ = out_tx.send(encode_ws_packet(ws_pkt::CLOSE, 0, &[r])).await;
                finish_writer(out_tx, writer_task).await;
                return Ok(());
            }
        }
        if session_token.is_none() {
            session_token = info_tok;
        }
    } else if policy.requires_auth() && session_token.is_none() {
        let _ = out_tx
            .send(encode_ws_packet(ws_pkt::CLOSE, 0, &[close_reason::AUTH_REQUIRED]))
            .await;
        finish_writer(out_tx, writer_task).await;
        return Ok(());
    }

    let principal = auth_proxy
        .as_ref()
        .map(|ap| Arc::new(ap.resolve_principal(session_token.as_deref(), disable_raw_tcp)));

    // Send initial CONTINUE on stream 0.
    let _ = out_tx
        .send(encode_ws_packet(ws_pkt::CONTINUE, 0, &INITIAL_BUFFER.to_le_bytes()))
        .await;

    struct StreamDropGuard {
        stream_id: u32,
        done_tx: mpsc::Sender<u32>,
    }
    impl Drop for StreamDropGuard {
        fn drop(&mut self) {
            let _ = self.done_tx.try_send(self.stream_id);
        }
    }

    struct StreamEntry {
        tx: mpsc::Sender<Vec<u8>>,
        task: JoinHandle<()>,
    }

    let mut streams: HashMap<u32, StreamEntry> = HashMap::new();
    let (done_tx, mut done_rx) = mpsc::channel::<u32>(128);
    let mut stream_limiter = policy.new_stream_limiter();

    loop {
        let msg = tokio::select! {
            done_id = done_rx.recv() => {
                if let Some(id) = done_id {
                    streams.remove(&id);
                }
                continue;
            }
            next_msg = ws_stream.next() => {
                match next_msg {
                    Some(Ok(m)) => m,
                    _ => break,
                }
            }
        };
        let Message::Binary(data) = msg else { continue };
        if data.len() < 5 {
            continue;
        }
        let pkt_type = data[0];
        let stream_id = u32::from_le_bytes(data[1..5].try_into().unwrap());
        let payload = &data[5..];

        match pkt_type {
            ws_pkt::CONNECT => {
                if payload.len() < 4
                    || !stream_limiter.allow()
                    || streams.len() >= policy.max_streams_per_session
                {
                    let reason = if payload.len() < 4 {
                        close_reason::INVALID_INFO
                    } else {
                        close_reason::THROTTLED
                    };
                    let _ = out_tx
                        .send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[reason]))
                        .await;
                    continue;
                }
                let stype = payload[0];
                let port = u16::from_le_bytes([payload[1], payload[2]]);
                let Ok(host) = std::str::from_utf8(&payload[3..]) else {
                    let _ = out_tx
                        .send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[close_reason::INVALID_INFO]))
                        .await;
                    continue;
                };

                let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(INITIAL_BUFFER as usize);
                let out_tx_c = out_tx.clone();
                let policy_c = policy.clone();
                let host_owned = host.to_string();
                let done_tx_c = done_tx.clone();

                if stype == ws_stream_type::TCP {
                    if disable_raw_tcp || principal.as_ref().is_some_and(|p| !p.allow_raw_tcp) {
                        let _ = out_tx
                            .send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[close_reason::BLOCKED]))
                            .await;
                        continue;
                    }
                    let task = tokio::spawn(async move {
                        let _guard = StreamDropGuard {
                            stream_id,
                            done_tx: done_tx_c,
                        };
                        let addrs = match resolve_and_check_target(&host_owned, port, &policy_c).await {
                            Ok(a) => a,
                            Err(r) => {
                                let _ = out_tx_c.send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[r])).await;
                                return;
                            }
                        };
                        let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addrs[..])).await {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                let r = match e.kind() {
                                    std::io::ErrorKind::ConnectionRefused => close_reason::CONNECTION_REFUSED,
                                    std::io::ErrorKind::TimedOut => close_reason::CONNECT_TIMEOUT,
                                    _ => close_reason::UNREACHABLE,
                                };
                                let _ = out_tx_c.send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[r])).await;
                                return;
                            }
                            Err(_) => {
                                let _ = out_tx_c
                                    .send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[close_reason::CONNECT_TIMEOUT]))
                                    .await;
                                return;
                            }
                        };
                        let _ = tcp.set_nodelay(true);
                        let (mut tr, mut tw) = tcp.into_split();

                        let out_w = out_tx_c.clone();
                        let c2s = async move {
                            let mut received: u32 = 0;
                            while let Some(chunk) = in_rx.recv().await {
                                if tw.write_all(&chunk).await.is_err() {
                                    break;
                                }
                                received += 1;
                                if received >= INITIAL_BUFFER / 2 {
                                    received = 0;
                                    let cap = (INITIAL_BUFFER as usize).saturating_sub(in_rx.len()) as u32;
                                    let _ = out_w
                                        .send(encode_ws_packet(
                                            ws_pkt::CONTINUE,
                                            stream_id,
                                            &cap.to_le_bytes(),
                                        ))
                                        .await;
                                }
                            }
                        };
                        let out_r = out_tx_c.clone();
                        let s2c = async move {
                            let mut buf = vec![0u8; 32 * 1024];
                            loop {
                                match tr.read(&mut buf).await {
                                    Ok(0) => {
                                        let _ = out_r
                                            .send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[close_reason::VOLUNTARY]))
                                            .await;
                                        break;
                                    }
                                    Ok(n) => {
                                        if out_r
                                            .send(encode_ws_packet(ws_pkt::DATA, stream_id, &buf[..n]))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Err(_) => {
                                        let _ = out_r
                                            .send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[close_reason::NETWORK_ERROR]))
                                            .await;
                                        break;
                                    }
                                }
                            }
                        };
                        tokio::select! {
                            _ = c2s => {}
                            _ = s2c => {}
                        }
                    });
                    if let Some(old) = streams.insert(stream_id, StreamEntry { tx: in_tx, task }) {
                        old.task.abort();
                    }
                } else if stype == ws_stream_type::UDP {
                    let task = tokio::spawn(async move {
                        let _guard = StreamDropGuard {
                            stream_id,
                            done_tx: done_tx_c,
                        };
                        let addrs = match resolve_and_check_target(&host_owned, port, &policy_c).await {
                            Ok(a) => a,
                            Err(r) => {
                                let _ = out_tx_c.send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[r])).await;
                                return;
                            }
                        };
                        let target = addrs[0];
                        let bind_addr: SocketAddr = if target.is_ipv4() {
                            "0.0.0.0:0".parse().unwrap()
                        } else {
                            "[::]:0".parse().unwrap()
                        };
                        let Ok(sock) = UdpSocket::bind(bind_addr).await else { return };
                        if sock.connect(target).await.is_err() {
                            return;
                        }
                        let sock = Arc::new(sock);
                        let sock_r = Arc::clone(&sock);
                        let out_r = out_tx_c.clone();
                        let c2s = async move {
                            while let Some(chunk) = in_rx.recv().await {
                                if sock.send(&chunk).await.is_err() {
                                    break;
                                }
                            }
                        };
                        let s2c = async move {
                            let mut buf = vec![0u8; 4096];
                            loop {
                                match sock_r.recv(&mut buf).await {
                                    Ok(n) => {
                                        if out_r
                                            .send(encode_ws_packet(ws_pkt::DATA, stream_id, &buf[..n]))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        };
                        tokio::select! {
                            _ = c2s => {}
                            _ = s2c => {}
                        }
                    });
                    if let Some(old) = streams.insert(stream_id, StreamEntry { tx: in_tx, task }) {
                        old.task.abort();
                    }
                } else if stype == ws_stream_type::HTTP_PROXY {
                    let (Some(ap), Some(p)) = (auth_proxy.as_ref(), principal.as_ref()) else {
                        let _ = out_tx
                            .send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[close_reason::BLOCKED]))
                            .await;
                        continue;
                    };
                    let Some(route) = ap.get_route(&host_owned, p) else {
                        let reason = if p.allowed_routes.is_empty() && !ap.principals.is_empty() {
                            close_reason::AUTH_REQUIRED
                        } else {
                            close_reason::BLOCKED
                        };
                        let _ = out_tx
                            .send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[reason]))
                            .await;
                        continue;
                    };
                    let ap_c = Arc::clone(ap);
                    let task = tokio::spawn(async move {
                        let _guard = StreamDropGuard {
                            stream_id,
                            done_tx: done_tx_c,
                        };
                        let (client_io, relay_io) = tokio::io::duplex(64 * 1024);
                        let (mut rh_read, mut rh_write) = tokio::io::split(relay_io);
                        let out_w = out_tx_c.clone();
                        let c2s = async move {
                            let mut received: u32 = 0;
                            while let Some(chunk) = in_rx.recv().await {
                                if rh_write.write_all(&chunk).await.is_err() {
                                    break;
                                }
                                received += 1;
                                if received >= INITIAL_BUFFER / 2 {
                                    received = 0;
                                    let cap = (INITIAL_BUFFER as usize).saturating_sub(in_rx.len()) as u32;
                                    let _ = out_w
                                        .send(encode_ws_packet(
                                            ws_pkt::CONTINUE,
                                            stream_id,
                                            &cap.to_le_bytes(),
                                        ))
                                        .await;
                                }
                            }
                            let _ = rh_write.shutdown().await;
                        };
                        let out_r = out_tx_c.clone();
                        let s2c = async move {
                            let mut buf = vec![0u8; 32 * 1024];
                            loop {
                                match rh_read.read(&mut buf).await {
                                    Ok(0) => {
                                        let _ = out_r
                                            .send(encode_ws_packet(
                                                ws_pkt::CLOSE,
                                                stream_id,
                                                &[close_reason::VOLUNTARY],
                                            ))
                                            .await;
                                        break;
                                    }
                                    Ok(n) => {
                                        if out_r
                                            .send(encode_ws_packet(ws_pkt::DATA, stream_id, &buf[..n]))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Err(_) => {
                                        let _ = out_r
                                            .send(encode_ws_packet(
                                                ws_pkt::CLOSE,
                                                stream_id,
                                                &[close_reason::NETWORK_ERROR],
                                            ))
                                            .await;
                                        break;
                                    }
                                }
                            }
                        };
                        let proxy_fut = handle_http_proxy_io(client_io, route, ap_c, policy_c);
                        tokio::select! {
                            _ = proxy_fut => {}
                            _ = async { tokio::join!(c2s, s2c) } => {}
                        }
                    });
                    if let Some(old) = streams.insert(stream_id, StreamEntry { tx: in_tx, task }) {
                        old.task.abort();
                    }
                }
            }
            ws_pkt::DATA => {
                if let Some(entry) = streams.get(&stream_id) {
                    if entry.tx.try_send(payload.to_vec()).is_err() {
                        if let Some(removed) = streams.remove(&stream_id) {
                            removed.task.abort();
                        }
                        let _ = out_tx
                            .send(encode_ws_packet(
                                ws_pkt::CLOSE,
                                stream_id,
                                &[close_reason::THROTTLED],
                            ))
                            .await;
                    }
                }
            }
            ws_pkt::CLOSE => {
                if let Some(entry) = streams.remove(&stream_id) {
                    entry.task.abort();
                }
            }
            _ => {}
        }
    }

    for (_, entry) in streams.drain() {
        entry.task.abort();
    }
    finish_writer(out_tx, writer_task).await;
    Ok(())
}
