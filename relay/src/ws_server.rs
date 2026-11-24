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
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tracing::{debug, info, warn};

const INITIAL_BUFFER: u32 = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run_ws_server(
    bind: SocketAddr,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    policy: SecurityPolicy,
    motd: Option<String>,
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
        tokio::spawn(async move {
            let res = if let Some(acc) = acceptor {
                match acc.accept(stream).await {
                    Ok(tls_stream) => handle_ws_conn(tls_stream, peer, policy, motd).await,
                    Err(e) => Err(e.into()),
                }
            } else {
                handle_ws_conn(stream, peer, policy, motd).await
            };
            if let Err(err) = res {
                debug!(?err, %peer, "WebSocket session ended");
            }
        });
    }
}

async fn handle_ws_conn<S>(
    stream: S,
    peer: SocketAddr,
    policy: SecurityPolicy,
    motd: Option<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut is_v2 = false;
    let mut http_authed = false;
    let mut rejected = false;

    let ws = accept_hdr_async(stream, |req: &Request, mut resp: Response| {
        let origin = req.headers().get("origin").and_then(|v| v.to_str().ok());
        if !policy.check_origin(origin) {
            warn!(?origin, %peer, "Rejected WebSocket session: disallowed Origin");
            rejected = true;
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
                rejected = true;
                return Err(ErrorResponse::new(Some("Unauthorized".into())));
            }
            http_authed = true;
        }

        if let Some(proto) = req.headers().get("sec-websocket-protocol") {
            is_v2 = true;
            if let Ok(p) = proto.to_str() {
                if let Some(first) = p.split(',').next().map(str::trim).filter(|s| !s.is_empty()) {
                    if let Ok(val) = first.parse() {
                        resp.headers_mut().insert("sec-websocket-protocol", val);
                    }
                }
            }
        }
        Ok(resp)
    })
    .await?;

    let Some(_permit) = policy.try_acquire_session(peer.ip()) else {
        return Ok(());
    };

    let (mut ws_sink, mut ws_stream) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(512);

    let writer_task = tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            if ws_sink.send(Message::Binary(pkt.into())).await.is_err() {
                break;
            }
        }
    });

    if is_v2 {
        let mut exts = vec![Extension {
            id: ext_id::UDP,
            data: Vec::new(),
        }];
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

        // Wait for client INFO.
        let Some(Ok(Message::Binary(first))) = ws_stream.next().await else {
            writer_task.abort();
            return Ok(());
        };
        if first.len() < 5 || first[0] != ws_pkt::INFO {
            let _ = out_tx
                .send(encode_ws_packet(ws_pkt::CLOSE, 0, &[close_reason::INVALID_INFO]))
                .await;
            writer_task.abort();
            return Ok(());
        }
        let client_info = decode_info(&first[5..])?;
        if policy.requires_auth() && !http_authed {
            let tok = extract_token_from_info(&client_info);
            let reason = match tok {
                None => Some(close_reason::AUTH_REQUIRED),
                Some(ref t) if !policy.verify_token(Some(t.as_str())) => {
                    Some(close_reason::AUTH_INVALID_PASSWORD)
                }
                _ => None,
            };
            if let Some(r) = reason {
                let _ = out_tx.send(encode_ws_packet(ws_pkt::CLOSE, 0, &[r])).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                writer_task.abort();
                return Ok(());
            }
        }
    } else if policy.requires_auth() && !http_authed {
        let _ = out_tx
            .send(encode_ws_packet(ws_pkt::CLOSE, 0, &[close_reason::AUTH_REQUIRED]))
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        writer_task.abort();
        return Ok(());
    }

    // Send initial CONTINUE on stream 0.
    let _ = out_tx
        .send(encode_ws_packet(ws_pkt::CONTINUE, 0, &INITIAL_BUFFER.to_le_bytes()))
        .await;

    enum StreamEntry {
        Tcp {
            tx: mpsc::Sender<Vec<u8>>,
            task: JoinHandle<()>,
        },
        Udp {
            tx: mpsc::Sender<Vec<u8>>,
            task: JoinHandle<()>,
        },
    }

    let mut streams: HashMap<u32, StreamEntry> = HashMap::new();
    let mut stream_limiter = policy.new_stream_limiter();

    while let Some(msg) = ws_stream.next().await {
        let Ok(msg) = msg else { break };
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

                if stype == ws_stream_type::TCP {
                    let task = tokio::spawn(async move {
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
                                    let _ = out_w
                                        .send(encode_ws_packet(
                                            ws_pkt::CONTINUE,
                                            stream_id,
                                            &INITIAL_BUFFER.to_le_bytes(),
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
                    streams.insert(stream_id, StreamEntry::Tcp { tx: in_tx, task });
                } else if stype == ws_stream_type::UDP {
                    let task = tokio::spawn(async move {
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
                    streams.insert(stream_id, StreamEntry::Udp { tx: in_tx, task });
                }
            }
            ws_pkt::DATA => {
                if let Some(entry) = streams.get(&stream_id) {
                    let tx = match entry {
                        StreamEntry::Tcp { tx, .. } | StreamEntry::Udp { tx, .. } => tx,
                    };
                    let _ = tx.try_send(payload.to_vec());
                }
            }
            ws_pkt::CLOSE => {
                if let Some(entry) = streams.remove(&stream_id) {
                    match entry {
                        StreamEntry::Tcp { task, .. } | StreamEntry::Udp { task, .. } => task.abort(),
                    }
                }
            }
            _ => {}
        }
    }

    for (_, entry) in streams.drain() {
        match entry {
            StreamEntry::Tcp { task, .. } | StreamEntry::Udp { task, .. } => task.abort(),
        }
    }
    writer_task.abort();
    Ok(())
}
