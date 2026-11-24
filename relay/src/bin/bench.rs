use anyhow::Result;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use wisp_wt_relay::protocol::{
    InfoPayload, control_msg, encode_control_frame, encode_info, encode_ws_packet, stream_kind,
    ws_pkt, ws_stream_type,
};
use wisp_wt_relay::tls::ensure_crypto_provider;
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Endpoint};

#[derive(Debug, Parser)]
struct BenchArgs {
    #[arg(long, default_value = "127.0.0.1:4433")]
    wt_addr: String,
    #[arg(long, default_value = "127.0.0.1:4434")]
    ws_addr: String,
    #[arg(long, default_value = "127.0.0.1:9000")]
    origin_addr: SocketAddr,
    #[arg(long)]
    cert_sha256_hex: String,
    #[arg(long, default_value_t = false)]
    start_origin: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct ScenarioAResult {
    transport: String,
    small_p50_ms: f64,
    small_p95_ms: f64,
    small_p99_ms: f64,
    small_max_ms: f64,
    bulk_mbps: f64,
    total_ms: f64,
}

#[derive(Debug, Serialize)]
struct ScenarioBResult {
    transport: String,
    total_ms: f64,
    stream_p50_ms: f64,
    stream_p95_ms: f64,
    stream_p99_ms: f64,
}

#[derive(Debug, Serialize)]
struct BenchOutput {
    scenario_a: Vec<ScenarioAResult>,
    scenario_b: Vec<ScenarioBResult>,
}

async fn run_origin_server(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let chunk = vec![0xABu8; 64 * 1024];
    loop {
        let (mut sock, _) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let chunk = chunk.clone();
        tokio::spawn(async move {
            let mut req = [0u8; 8];
            if sock.read_exact(&mut req).await.is_err() {
                return;
            }
            let mut remaining = u64::from_le_bytes(req) as usize;
            while remaining > 0 {
                let n = remaining.min(chunk.len());
                if sock.write_all(&chunk[..n]).await.is_err() {
                    break;
                }
                remaining -= n;
            }
            let _ = sock.shutdown().await;
        });
    }
}

fn parse_hex_32(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        anyhow::bail!("Expected 32-byte hex digest");
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Expected 32-byte hex digest"))?;
    Ok(arr)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

async fn wt_fetch(
    conn: &wtransport::Connection,
    origin_host: &str,
    origin_port: u16,
    size: u64,
) -> Result<f64> {
    let t0 = Instant::now();
    let (mut send, mut recv) = conn.open_bi().await?.await?;
    let host_b = origin_host.as_bytes();
    let mut req = Vec::with_capacity(6 + host_b.len() + 8);
    req.push(stream_kind::TCP);
    req.push(0x01);
    req.extend_from_slice(&origin_port.to_le_bytes());
    req.extend_from_slice(&(host_b.len() as u16).to_le_bytes());
    req.extend_from_slice(host_b);
    send.write_all(&req).await?;

    let mut resp = [0u8; 2];
    recv.read_exact(&mut resp).await?;
    if resp[0] != 0x00 {
        anyhow::bail!("WT stream connect failed: 0x{:02x}", resp[0]);
    }
    send.write_all(&size.to_le_bytes()).await?;
    send.finish().await?;

    let mut got = 0usize;
    let mut buf = vec![0u8; 32 * 1024];
    while got < size as usize {
        match recv.read(&mut buf).await? {
            Some(0) | None => break,
            Some(n) => got += n,
        }
    }
    if got != size as usize {
        anyhow::bail!("WT short read: {got} != {size}");
    }
    Ok(t0.elapsed().as_secs_f64() * 1000.0)
}

type WsStreamMap = Arc<Mutex<HashMap<u32, (usize, usize, Instant, oneshot::Sender<f64>)>>>;

struct WsClient {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    streams: WsStreamMap,
    next_id: std::sync::atomic::AtomicU32,
}

impl WsClient {
    async fn connect(url: &str) -> Result<Arc<Self>> {
        let (ws, _) = connect_async(url).await?;
        let (mut sink, mut stream) = ws.split();
        // Wait for initial CONTINUE on stream 0.
        let _ = stream.next().await;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
        let streams: WsStreamMap = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                if sink.send(Message::Binary(pkt.into())).await.is_err() {
                    break;
                }
            }
        });

        let streams_r = Arc::clone(&streams);
        tokio::spawn(async move {
            while let Some(Ok(Message::Binary(data))) = stream.next().await {
                if data.len() < 5 {
                    continue;
                }
                let id = u32::from_le_bytes(data[1..5].try_into().unwrap());
                if data[0] == ws_pkt::DATA {
                    let mut guard = streams_r.lock().await;
                    if let Some(entry) = guard.get_mut(&id) {
                        entry.0 += data.len() - 5;
                        if entry.0 >= entry.1 {
                            let (_, _, t0, done_tx) = guard.remove(&id).unwrap();
                            let _ = done_tx.send(t0.elapsed().as_secs_f64() * 1000.0);
                        }
                    }
                } else if data[0] == ws_pkt::CLOSE {
                    let mut guard = streams_r.lock().await;
                    if let Some((_, _, t0, done_tx)) = guard.remove(&id) {
                        let _ = done_tx.send(t0.elapsed().as_secs_f64() * 1000.0);
                    }
                }
            }
        });

        Ok(Arc::new(Self {
            tx,
            streams,
            next_id: std::sync::atomic::AtomicU32::new(1),
        }))
    }

    async fn fetch(&self, host: &str, port: u16, size: u64) -> Result<f64> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (done_tx, done_rx) = oneshot::channel();
        let t0 = Instant::now();
        self.streams
            .lock()
            .await
            .insert(id, (0, size as usize, t0, done_tx));

        let mut creq = vec![ws_stream_type::TCP];
        creq.extend_from_slice(&port.to_le_bytes());
        creq.extend_from_slice(host.as_bytes());
        self.tx
            .send(encode_ws_packet(ws_pkt::CONNECT, id, &creq))
            .await?;
        self.tx
            .send(encode_ws_packet(ws_pkt::DATA, id, &size.to_le_bytes()))
            .await?;

        Ok(done_rx.await?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    ensure_crypto_provider();
    let args = BenchArgs::parse();

    if args.start_origin {
        let addr = args.origin_addr;
        tokio::spawn(async move {
            let _ = run_origin_server(addr).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let origin_host = args.origin_addr.ip().to_string();
    let origin_port = args.origin_addr.port();

    // Connect WebTransport
    let hash = Sha256Digest::new(parse_hex_32(&args.cert_sha256_hex)?);
    let wt_cfg = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([hash])
        .build();
    let wt_ep = Endpoint::client(wt_cfg)?;
    let wt_conn = wt_ep.connect(format!("https://{}/", args.wt_addr)).await?;
    let (mut cs, mut cr) = wt_conn.open_bi().await?.await?;
    cs.write_all(&[stream_kind::CONTROL]).await?;
    let info = encode_info(&InfoPayload {
        major: 2,
        minor: 1,
        extensions: vec![],
    });
    cs.write_all(&encode_control_frame(control_msg::INFO, &info))
        .await?;
    let mut hdr = [0u8; 5];
    for _ in 0..2 {
        cr.read_exact(&mut hdr).await?;
        let len = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
        let mut buf = vec![0u8; len];
        cr.read_exact(&mut buf).await?;
    }

    // Connect WebSocket
    let ws_client = WsClient::connect(&format!("ws://{}/", args.ws_addr)).await?;

    // Scenario A: 2x 4 MiB bulk + 24x 4 KiB interactive RPCs
    let mut scenario_a = Vec::new();
    for (name, use_wt) in [("Wisp-WS", false), ("Wisp-WT", true)] {
        let t0 = Instant::now();
        let mut bulk_handles = Vec::new();
        for _ in 0..2 {
            let h = origin_host.clone();
            if use_wt {
                let c = wt_conn.clone();
                bulk_handles.push(tokio::spawn(async move {
                    wt_fetch(&c, &h, origin_port, 4 * 1024 * 1024).await
                }));
            } else {
                let c = Arc::clone(&ws_client);
                bulk_handles.push(tokio::spawn(async move {
                    c.fetch(&h, origin_port, 4 * 1024 * 1024).await
                }));
            }
        }

        let mut small_lats = Vec::new();
        for _ in 0..24 {
            let lat = if use_wt {
                wt_fetch(&wt_conn, &origin_host, origin_port, 4096).await?
            } else {
                ws_client.fetch(&origin_host, origin_port, 4096).await?
            };
            small_lats.push(lat);
        }
        for bh in bulk_handles {
            bh.await??;
        }
        let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
        small_lats.sort_by(|a, b| a.total_cmp(b));
        let bulk_mbps = (8.0 * 1024.0 * 1024.0) / (total_ms / 1000.0) / (1024.0 * 1024.0);
        scenario_a.push(ScenarioAResult {
            transport: name.to_string(),
            small_p50_ms: percentile(&small_lats, 0.50),
            small_p95_ms: percentile(&small_lats, 0.95),
            small_p99_ms: percentile(&small_lats, 0.99),
            small_max_ms: *small_lats.last().unwrap_or(&0.0),
            bulk_mbps,
            total_ms,
        });
    }

    // Scenario B: 16 parallel streams (12x 256 KiB + 4x 8 KiB)
    let mut scenario_b = Vec::new();
    for (name, use_wt) in [("Wisp-WS", false), ("Wisp-WT", true)] {
        let t0 = Instant::now();
        let mut handles = Vec::new();
        for i in 0..16 {
            let size = if i < 12 { 256 * 1024 } else { 8 * 1024 };
            let h = origin_host.clone();
            if use_wt {
                let c = wt_conn.clone();
                handles.push(tokio::spawn(async move {
                    wt_fetch(&c, &h, origin_port, size).await
                }));
            } else {
                let c = Arc::clone(&ws_client);
                handles.push(tokio::spawn(
                    async move { c.fetch(&h, origin_port, size).await },
                ));
            }
        }
        let mut lats = Vec::new();
        for h in handles {
            lats.push(h.await??);
        }
        let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
        lats.sort_by(|a, b| a.total_cmp(b));
        scenario_b.push(ScenarioBResult {
            transport: name.to_string(),
            total_ms,
            stream_p50_ms: percentile(&lats, 0.50),
            stream_p95_ms: percentile(&lats, 0.95),
            stream_p99_ms: percentile(&lats, 0.99),
        });
    }

    let out = BenchOutput {
        scenario_a,
        scenario_b,
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Scenario A (HoL): {:#?}", out.scenario_a);
        println!("Scenario B (Parallel): {:#?}", out.scenario_b);
    }
    Ok(())
}
