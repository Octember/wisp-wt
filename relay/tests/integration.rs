use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use wisp_wt_relay::config::RelayConfig;
use wisp_wt_relay::protocol::{
    Extension, InfoPayload, close_reason, control_msg, decode_varint, encode_control_frame,
    encode_info, encode_varint, encode_ws_packet, ext_id, stream_kind, ws_pkt, ws_stream_type,
};
use wisp_wt_relay::security::SecurityPolicy;
use wisp_wt_relay::tls::load_or_generate_tls;
use wisp_wt_relay::{ws_server, wt_server};
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Endpoint};

async fn spawn_tcp_echo() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

async fn spawn_udp_echo() -> Result<SocketAddr> {
    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = sock.local_addr()?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    Ok(addr)
}

fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

fn free_tcp_port() -> u16 {
    let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

#[tokio::test]
async fn wt_tcp_concurrent_and_udp_echo() -> Result<()> {
    let echo_tcp = spawn_tcp_echo().await?;
    let echo_udp = spawn_udp_echo().await?;
    let wt_port = free_udp_port();
    let ws_port = free_tcp_port();

    let mut cfg = RelayConfig::default();
    cfg.wt_bind = format!("127.0.0.1:{wt_port}").parse()?;
    cfg.ws_bind = format!("127.0.0.1:{ws_port}").parse()?;
    cfg.allow_loopback = true;
    cfg.allow_any_origin = true;

    let tls = load_or_generate_tls(None, None, true, &[])?;
    let hash = Sha256Digest::new(tls.cert_sha256);
    let policy = SecurityPolicy::from_config(&cfg);

    tokio::spawn(wt_server::run_wt_server(
        cfg.wt_bind,
        tls.identity,
        policy.clone(),
        Some("test-motd".into()),
    ));
    tokio::spawn(ws_server::run_ws_server(cfg.ws_bind, None, policy, None));
    tokio::time::sleep(Duration::from_millis(80)).await;

    let client_cfg = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([hash])
        .build();
    let client = Endpoint::client(client_cfg)?;
    let conn = client.connect(format!("https://127.0.0.1:{wt_port}/")).await?;

    // Open control stream
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?.await?;
    ctrl_send.write_all(&[stream_kind::CONTROL]).await?;
    let info = encode_info(&InfoPayload {
        major: 2,
        minor: 1,
        extensions: vec![Extension {
            id: ext_id::UDP,
            data: vec![],
        }],
    });
    ctrl_send
        .write_all(&encode_control_frame(control_msg::INFO, &info))
        .await?;

    let mut hdr = [0u8; 5];
    ctrl_recv.read_exact(&mut hdr).await?;
    assert_eq!(hdr[0], control_msg::INFO);
    let len = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
    let mut buf = vec![0u8; len];
    ctrl_recv.read_exact(&mut buf).await?;

    ctrl_recv.read_exact(&mut hdr).await?;
    assert_eq!(hdr[0], control_msg::READY);
    let rlen = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
    let mut rbuf = vec![0u8; rlen];
    ctrl_recv.read_exact(&mut rbuf).await?;

    // 10 concurrent TCP streams
    let mut handles = Vec::new();
    for i in 0..10u32 {
        let conn_c = conn.clone();
        handles.push(tokio::spawn(async move {
            let (mut s, mut r) = conn_c.open_bi().await?.await?;
            let host = b"127.0.0.1";
            let mut req = Vec::new();
            req.push(stream_kind::TCP);
            req.push(0x01);
            req.extend_from_slice(&echo_tcp.port().to_le_bytes());
            req.extend_from_slice(&(host.len() as u16).to_le_bytes());
            req.extend_from_slice(host);
            s.write_all(&req).await?;

            let mut resp = [0u8; 2];
            r.read_exact(&mut resp).await?;
            assert_eq!(resp[0], 0x00);

            let msg = format!("hello-stream-{i}");
            s.write_all(msg.as_bytes()).await?;
            let mut got = vec![0u8; msg.len()];
            r.read_exact(&mut got).await?;
            assert_eq!(got, msg.as_bytes());
            s.finish().await?;
            Ok::<(), anyhow::Error>(())
        }));
    }
    for h in handles {
        h.await??;
    }

    // UDP datagram echo
    let mut bind_payload = Vec::new();
    bind_payload.extend_from_slice(&1u32.to_le_bytes());
    bind_payload.extend_from_slice(&echo_udp.port().to_le_bytes());
    bind_payload.extend_from_slice(&9u16.to_le_bytes());
    bind_payload.extend_from_slice(b"127.0.0.1");
    ctrl_send
        .write_all(&encode_control_frame(control_msg::UDP_BIND, &bind_payload))
        .await?;

    ctrl_recv.read_exact(&mut hdr).await?;
    assert_eq!(hdr[0], control_msg::UDP_BOUND);
    let blen = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
    let mut bbuf = vec![0u8; blen];
    ctrl_recv.read_exact(&mut bbuf).await?;
    assert_eq!(bbuf[4], 0x00);

    let mut dgram = Vec::new();
    encode_varint(1, &mut dgram)?;
    dgram.extend_from_slice(b"ping-udp");
    conn.send_datagram(dgram)?;

    let recv_dg = tokio::time::timeout(Duration::from_secs(2), conn.receive_datagram()).await??;
    let (fid, off) = decode_varint(&recv_dg)?;
    assert_eq!(fid, 1);
    assert_eq!(&recv_dg[off..], b"ping-udp");

    // WebSocket Wisp v1 fallback test
    let (mut ws, _) = connect_async(format!("ws://127.0.0.1:{ws_port}/")).await?;
    let first = ws.next().await.unwrap()?;
    let Message::Binary(b) = first else { panic!("expected binary") };
    assert_eq!(b[0], ws_pkt::CONTINUE);

    let mut creq = vec![ws_stream_type::TCP];
    creq.extend_from_slice(&echo_tcp.port().to_le_bytes());
    creq.extend_from_slice(b"127.0.0.1");
    ws.send(Message::Binary(encode_ws_packet(ws_pkt::CONNECT, 1, &creq).into()))
        .await?;
    ws.send(Message::Binary(encode_ws_packet(ws_pkt::DATA, 1, b"ws-echo").into()))
        .await?;

    let reply = ws.next().await.unwrap()?;
    let Message::Binary(rb) = reply else { panic!("expected binary") };
    assert_eq!(rb[0], ws_pkt::DATA);
    assert_eq!(&rb[5..], b"ws-echo");

    Ok(())
}

#[tokio::test]
async fn ssrf_blocks_loopback_when_disabled() -> Result<()> {
    let wt_port = free_udp_port();
    let ws_port = free_tcp_port();

    let mut cfg = RelayConfig::default();
    cfg.wt_bind = format!("127.0.0.1:{wt_port}").parse()?;
    cfg.ws_bind = format!("127.0.0.1:{ws_port}").parse()?;
    cfg.allow_loopback = false;
    cfg.allow_any_origin = true;

    let tls = load_or_generate_tls(None, None, true, &[])?;
    let hash = Sha256Digest::new(tls.cert_sha256);
    let policy = SecurityPolicy::from_config(&cfg);
    tokio::spawn(wt_server::run_wt_server(cfg.wt_bind, tls.identity, policy, None));
    tokio::time::sleep(Duration::from_millis(60)).await;

    let client_cfg = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([hash])
        .build();
    let client = Endpoint::client(client_cfg)?;
    let conn = client.connect(format!("https://127.0.0.1:{wt_port}/")).await?;

    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?.await?;
    ctrl_send.write_all(&[stream_kind::CONTROL]).await?;
    let info = encode_info(&InfoPayload {
        major: 2,
        minor: 1,
        extensions: vec![],
    });
    ctrl_send
        .write_all(&encode_control_frame(control_msg::INFO, &info))
        .await?;
    let mut hdr = [0u8; 5];
    for _ in 0..2 {
        ctrl_recv.read_exact(&mut hdr).await?;
        let len = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
        let mut buf = vec![0u8; len];
        ctrl_recv.read_exact(&mut buf).await?;
    }

    let (mut s, mut r) = conn.open_bi().await?.await?;
    let mut req = vec![stream_kind::TCP, 0x01];
    req.extend_from_slice(&80u16.to_le_bytes());
    req.extend_from_slice(&9u16.to_le_bytes());
    req.extend_from_slice(b"127.0.0.1");
    s.write_all(&req).await?;

    let mut resp = [0u8; 2];
    r.read_exact(&mut resp).await?;
    assert_eq!(resp[0], close_reason::BLOCKED);
    Ok(())
}
