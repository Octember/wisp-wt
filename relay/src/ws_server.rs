use crate::auth_proxy::{AuthProxy, handle_http_proxy_io};
use crate::protocol::{
    Extension, InfoPayload, close_reason, decode_info, encode_info, encode_ws_packet, ext_id,
    extract_token_from_info, ws_pkt, ws_stream_type,
};
use crate::security::{SecurityPolicy, connect_tcp, connect_udp, extract_http_token};
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
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
    let listener = TcpListener::bind(bind)
        .await
        .context("Bind WebSocket server")?;
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

    #[allow(clippy::result_large_err)]
    let ws = accept_hdr_async_with_config(
        stream,
        |req: &Request, mut resp: Response| {
            let origin = req.headers().get("origin").and_then(|v| v.to_str().ok());
            if !policy.check_origin(origin) {
                warn!(?origin, %peer, "Rejected WebSocket session: disallowed Origin");
                return Err(ErrorResponse::new(Some("Forbidden origin".into())));
            }

            let path = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let auth_hdr = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok());
            let token = extract_http_token(path, auth_hdr);
            if token.is_some() {
                if !policy.verify_token(token.as_deref()) {
                    return Err(ErrorResponse::new(Some("Unauthorized".into())));
                }
                http_token = token;
            }

            if let Some(proto) = req.headers().get("sec-websocket-protocol")
                && let Ok(p) = proto.to_str()
                && p.split(',').map(str::trim).any(|s| s == "wisp-v2")
            {
                is_v2 = true;
                if let Ok(val) = "wisp-v2".parse() {
                    resp.headers_mut().insert("sec-websocket-protocol", val);
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
        let _ = out_tx
            .send(encode_ws_packet(ws_pkt::INFO, 0, &info_bytes))
            .await;

        // Wait for client INFO with timeout.
        let info_msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws_stream.next()).await;
        let Ok(Some(Ok(Message::Binary(first)))) = info_msg else {
            finish_writer(out_tx, writer_task).await;
            return Ok(());
        };
        if first.len() < 5 || first[0] != ws_pkt::INFO {
            let _ = out_tx
                .send(encode_ws_packet(
                    ws_pkt::CLOSE,
                    0,
                    &[close_reason::INVALID_INFO],
                ))
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
            .send(encode_ws_packet(
                ws_pkt::CLOSE,
                0,
                &[close_reason::AUTH_REQUIRED],
            ))
            .await;
        finish_writer(out_tx, writer_task).await;
        return Ok(());
    }

    let principal = auth_proxy
        .as_ref()
        .map(|ap| Arc::new(ap.resolve_principal(session_token.as_deref(), disable_raw_tcp)));

    // Send initial CONTINUE on stream 0.
    let _ = out_tx
        .send(encode_ws_packet(
            ws_pkt::CONTINUE,
            0,
            &INITIAL_BUFFER.to_le_bytes(),
        ))
        .await;

    struct StreamEntry {
        instance: u64,
        tx: mpsc::Sender<Vec<u8>>,
        task: JoinHandle<()>,
    }

    let mut streams: HashMap<u32, StreamEntry> = HashMap::new();
    let (done_tx, mut done_rx) = mpsc::channel::<(u32, u64)>(128);
    let mut next_instance: u64 = 0;
    let mut stream_limiter = policy.new_stream_limiter();

    loop {
        let msg = tokio::select! {
            done_id = done_rx.recv() => {
                if let Some((id, inst)) = done_id
                    && streams.get(&id).is_some_and(|e| e.instance == inst)
                {
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
                        .send(encode_ws_packet(
                            ws_pkt::CLOSE,
                            stream_id,
                            &[close_reason::INVALID_INFO],
                        ))
                        .await;
                    continue;
                };

                let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(INITIAL_BUFFER as usize);
                next_instance = next_instance.wrapping_add(1);
                let instance = next_instance;
                let guard = StreamDropGuard {
                    stream_id,
                    instance,
                    done_tx: done_tx.clone(),
                };

                let task = match stype {
                    ws_stream_type::TCP => {
                        if disable_raw_tcp || principal.as_ref().is_some_and(|p| !p.allow_raw_tcp) {
                            send_ws_close(&out_tx, stream_id, close_reason::BLOCKED).await;
                            continue;
                        }
                        spawn_ws_tcp(
                            guard,
                            stream_id,
                            host.to_string(),
                            port,
                            policy.clone(),
                            in_rx,
                            out_tx.clone(),
                        )
                    }
                    ws_stream_type::UDP => spawn_ws_udp(
                        guard,
                        stream_id,
                        host.to_string(),
                        port,
                        policy.clone(),
                        in_rx,
                        out_tx.clone(),
                    ),
                    ws_stream_type::HTTP_PROXY => {
                        let (ap, route) = match AuthProxy::authorize_route(
                            auth_proxy.as_ref(),
                            principal.as_deref(),
                            host,
                        ) {
                            Ok(res) => res,
                            Err(reason) => {
                                send_ws_close(&out_tx, stream_id, reason).await;
                                continue;
                            }
                        };
                        spawn_ws_http_proxy(
                            guard,
                            stream_id,
                            route,
                            ap,
                            policy.clone(),
                            in_rx,
                            out_tx.clone(),
                        )
                    }
                    _ => {
                        send_ws_close(&out_tx, stream_id, close_reason::INVALID_INFO).await;
                        continue;
                    }
                };
                if let Some(old) = streams.insert(
                    stream_id,
                    StreamEntry {
                        instance,
                        tx: in_tx,
                        task,
                    },
                ) {
                    old.task.abort();
                }
            }
            ws_pkt::DATA => {
                if let Some(entry) = streams.get(&stream_id)
                    && entry.tx.try_send(payload.to_vec()).is_err()
                {
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

struct StreamDropGuard {
    stream_id: u32,
    instance: u64,
    done_tx: mpsc::Sender<(u32, u64)>,
}

impl Drop for StreamDropGuard {
    fn drop(&mut self) {
        let _ = self.done_tx.try_send((self.stream_id, self.instance));
    }
}

async fn send_ws_close(out_tx: &mpsc::Sender<Vec<u8>>, stream_id: u32, reason: u8) {
    let _ = out_tx
        .send(encode_ws_packet(ws_pkt::CLOSE, stream_id, &[reason]))
        .await;
}

async fn bridge_ws_io<IO: AsyncRead + AsyncWrite + Unpin>(
    io: IO,
    stream_id: u32,
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Vec<u8>>,
) {
    let (mut reader, mut writer) = tokio::io::split(io);
    let out_w = out_tx.clone();
    let c2s = async move {
        let mut received: u32 = 0;
        while let Some(chunk) = in_rx.recv().await {
            if writer.write_all(&chunk).await.is_err() {
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
        let _ = writer.shutdown().await;
    };
    let s2c = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    send_ws_close(&out_tx, stream_id, close_reason::VOLUNTARY).await;
                    break;
                }
                Ok(n) => {
                    if out_tx
                        .send(encode_ws_packet(ws_pkt::DATA, stream_id, &buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    send_ws_close(&out_tx, stream_id, close_reason::NETWORK_ERROR).await;
                    break;
                }
            }
        }
    };
    tokio::join!(c2s, s2c);
}

fn spawn_ws_tcp(
    guard: StreamDropGuard,
    stream_id: u32,
    host: String,
    port: u16,
    policy: SecurityPolicy,
    in_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Vec<u8>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _guard = guard;
        let tcp = match connect_tcp(&host, port, &policy, CONNECT_TIMEOUT).await {
            Ok(s) => s,
            Err(r) => {
                send_ws_close(&out_tx, stream_id, r).await;
                return;
            }
        };
        let _ = tcp.set_nodelay(true);
        bridge_ws_io(tcp, stream_id, in_rx, out_tx).await;
    })
}

fn spawn_ws_udp(
    guard: StreamDropGuard,
    stream_id: u32,
    host: String,
    port: u16,
    policy: SecurityPolicy,
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Vec<u8>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _guard = guard;
        let sock = match connect_udp(&host, port, &policy).await {
            Ok(s) => Arc::new(s),
            Err(r) => {
                send_ws_close(&out_tx, stream_id, r).await;
                return;
            }
        };
        let sock_r = Arc::clone(&sock);
        let out_r = out_tx.clone();
        let c2s = async move {
            while let Some(chunk) = in_rx.recv().await {
                if sock.send(&chunk).await.is_err() {
                    break;
                }
            }
        };
        let s2c = async move {
            let mut buf = vec![0u8; 4096];
            while let Ok(n) = sock_r.recv(&mut buf).await {
                if out_r
                    .send(encode_ws_packet(ws_pkt::DATA, stream_id, &buf[..n]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        };
        tokio::select! {
            _ = c2s => {}
            _ = s2c => {}
        }
    })
}

fn spawn_ws_http_proxy(
    guard: StreamDropGuard,
    stream_id: u32,
    route: Arc<crate::auth_proxy::CompiledRoute>,
    ap: Arc<AuthProxy>,
    policy: SecurityPolicy,
    in_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Vec<u8>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _guard = guard;
        let (client_io, relay_io) = tokio::io::duplex(64 * 1024);
        tokio::join!(
            async move {
                let _ = handle_http_proxy_io(client_io, route, ap, policy).await;
            },
            bridge_ws_io(relay_io, stream_id, in_rx, out_tx),
        );
    })
}
