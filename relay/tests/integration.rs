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

    let cfg = RelayConfig {
        wt_bind: format!("127.0.0.1:{wt_port}").parse()?,
        ws_bind: format!("127.0.0.1:{ws_port}").parse()?,
        allow_loopback: true,
        allow_any_origin: true,
        ..Default::default()
    };

    let tls = load_or_generate_tls(None, None, true, &[])?;
    let hash = Sha256Digest::new(tls.cert_sha256);
    let policy = SecurityPolicy::from_config(&cfg);

    tokio::spawn(wt_server::run_wt_server(
        cfg.wt_bind,
        tls.identity,
        policy.clone(),
        Some("test-motd".into()),
        None,
        false,
    ));
    tokio::spawn(ws_server::run_ws_server(
        cfg.ws_bind,
        None,
        policy,
        None,
        None,
        false,
    ));
    tokio::time::sleep(Duration::from_millis(80)).await;

    let client_cfg = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([hash])
        .build();
    let client = Endpoint::client(client_cfg)?;
    let conn = client
        .connect(format!("https://127.0.0.1:{wt_port}/"))
        .await?;

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
    let Message::Binary(b) = first else {
        panic!("expected binary")
    };
    assert_eq!(b[0], ws_pkt::CONTINUE);

    let mut creq = vec![ws_stream_type::TCP];
    creq.extend_from_slice(&echo_tcp.port().to_le_bytes());
    creq.extend_from_slice(b"127.0.0.1");
    ws.send(Message::Binary(
        encode_ws_packet(ws_pkt::CONNECT, 1, &creq).into(),
    ))
    .await?;
    ws.send(Message::Binary(
        encode_ws_packet(ws_pkt::DATA, 1, b"ws-echo").into(),
    ))
    .await?;

    let reply = ws.next().await.unwrap()?;
    let Message::Binary(rb) = reply else {
        panic!("expected binary")
    };
    assert_eq!(rb[0], ws_pkt::DATA);
    assert_eq!(&rb[5..], b"ws-echo");

    Ok(())
}

#[tokio::test]
async fn ssrf_blocks_loopback_when_disabled() -> Result<()> {
    let wt_port = free_udp_port();
    let ws_port = free_tcp_port();

    let cfg = RelayConfig {
        wt_bind: format!("127.0.0.1:{wt_port}").parse()?,
        ws_bind: format!("127.0.0.1:{ws_port}").parse()?,
        allow_loopback: false,
        allow_any_origin: true,
        ..Default::default()
    };

    let tls = load_or_generate_tls(None, None, true, &[])?;
    let hash = Sha256Digest::new(tls.cert_sha256);
    let policy = SecurityPolicy::from_config(&cfg);
    tokio::spawn(wt_server::run_wt_server(
        cfg.wt_bind,
        tls.identity,
        policy,
        None,
        None,
        false,
    ));
    tokio::time::sleep(Duration::from_millis(60)).await;

    let client_cfg = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([hash])
        .build();
    let client = Endpoint::client(client_cfg)?;
    let conn = client
        .connect(format!("https://127.0.0.1:{wt_port}/"))
        .await?;

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

#[tokio::test]
async fn ssrf_trailing_dot_and_extended_cidrs() {
    let cfg = RelayConfig {
        allow_loopback: false,
        block_hosts: vec!["blocked.example".to_string()],
        ..Default::default()
    };
    let policy = SecurityPolicy::from_config(&cfg);

    assert_eq!(
        wisp_wt_relay::security::resolve_and_check_target("blocked.example.", 80, &policy).await,
        Err(close_reason::BLOCKED)
    );

    use std::net::IpAddr;
    use wisp_wt_relay::security::is_disallowed_ip;

    for ip_str in [
        "0.0.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "240.0.0.1",
        "::1",
        "64:ff9b::1",
        "64:ff9b:1::1",
        "2002::1",
        "2001::1",
        "fec0::1",
        "2001:db8::1",
    ] {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(is_disallowed_ip(ip), "expected {ip_str} to be disallowed");
    }
}

#[tokio::test]
async fn ws_over_260_sequential_tcp_streams_no_slot_leak() -> anyhow::Result<()> {
    let echo_tcp = spawn_tcp_echo().await?;
    let ws_port = free_tcp_port();
    let cfg = RelayConfig {
        wt_bind: format!("127.0.0.1:{}", free_udp_port()).parse()?,
        ws_bind: format!("127.0.0.1:{ws_port}").parse()?,
        allow_any_origin: true,
        allow_loopback: true,
        max_streams_per_session: 64,
        streams_per_sec: 10_000.0,
        streams_burst: 10_000.0,
        ..Default::default()
    };

    let _relay = tokio::spawn(async move {
        let _ = wisp_wt_relay::run_relay(cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (mut ws, _) = connect_async(format!("ws://127.0.0.1:{ws_port}/")).await?;
    let _ = ws.next().await.unwrap()?; // initial CONTINUE

    for sid in 1..=265u32 {
        let mut creq = vec![ws_stream_type::TCP];
        creq.extend_from_slice(&echo_tcp.port().to_le_bytes());
        creq.extend_from_slice(b"127.0.0.1");
        ws.send(Message::Binary(
            encode_ws_packet(ws_pkt::CONNECT, sid, &creq).into(),
        ))
        .await?;
        ws.send(Message::Binary(
            encode_ws_packet(ws_pkt::DATA, sid, b"hi").into(),
        ))
        .await?;

        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await?
            .unwrap()?;
        let Message::Binary(rb) = msg else {
            panic!("expected binary");
        };
        assert_eq!(rb[0], ws_pkt::DATA, "stream {sid} failed");
        assert_eq!(&rb[5..], b"hi");

        ws.send(Message::Binary(
            encode_ws_packet(ws_pkt::CLOSE, sid, &[0x02]).into(),
        ))
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn wt_fragmented_control_frames() -> anyhow::Result<()> {
    let wt_port = free_udp_port();
    let cfg = RelayConfig {
        wt_bind: format!("127.0.0.1:{wt_port}").parse()?,
        allow_any_origin: true,
        allow_loopback: true,
        ..Default::default()
    };

    let tls = load_or_generate_tls(None, None, true, &[])?;
    let cert_hash = tls.cert_sha256;
    let policy = SecurityPolicy::from_config(&cfg);
    tokio::spawn(wt_server::run_wt_server(
        cfg.wt_bind,
        tls.identity,
        policy,
        None,
        None,
        false,
    ));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let client = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([cert_hash.into()])
            .build(),
    )?;
    let conn = client
        .connect(format!("https://127.0.0.1:{wt_port}/"))
        .await?;
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?.await?;

    let info_payload = encode_info(&InfoPayload {
        major: 2,
        minor: 1,
        extensions: vec![],
    });
    let frame = encode_control_frame(control_msg::INFO, &info_payload);
    // Write 0x00 stream kind + fragmented INFO frame
    ctrl_send.write_all(&[stream_kind::CONTROL]).await?;
    for chunk in frame.chunks(2) {
        ctrl_send.write_all(chunk).await?;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut hdr = [0u8; 5];
    ctrl_recv.read_exact(&mut hdr).await?;
    assert_eq!(hdr[0], control_msg::INFO);
    let len = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
    let mut buf = vec![0u8; len];
    ctrl_recv.read_exact(&mut buf).await?;
    Ok(())
}

#[tokio::test]
async fn auth_proxy_end_to_end_and_disable_raw_tcp() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Mock upstream HTTP/1.1 server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = upstream_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let resp = if req.starts_with("GET /redirect ") {
                    "HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    let has_secret = req.to_ascii_lowercase().contains("x-api-key: secret-123");
                    let has_client_auth = req
                        .to_ascii_lowercase()
                        .contains("authorization: client-spoof");
                    let body = format!("secret={has_secret};spoof={has_client_auth}");
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });

    let cfg_path =
        std::env::temp_dir().join(format!("wisp_auth_proxy_{}.json", std::process::id()));
    let proxy_json = serde_json::json!({
        "routes": [{
            "id": "api",
            "upstream": format!("http://{upstream_addr}"),
            "allowed_methods": ["GET"],
            "allowed_paths": ["/v1/*", "/redirect"],
            "inject_headers": { "X-Api-Key": "secret-123" },
            "strip_request_headers": ["authorization"]
        }]
    });
    std::fs::write(&cfg_path, serde_json::to_string(&proxy_json)?)?;

    let wt_port = free_udp_port();
    let cfg = RelayConfig {
        wt_bind: format!("127.0.0.1:{wt_port}").parse()?,
        allow_any_origin: true,
        allow_loopback: true,
        disable_raw_tcp: true,
        ..Default::default()
    };

    let tls = load_or_generate_tls(None, None, true, &[])?;
    let cert_hash = tls.cert_sha256;
    let policy = SecurityPolicy::from_config(&cfg);
    let auth_proxy =
        std::sync::Arc::new(wisp_wt_relay::auth_proxy::AuthProxy::from_file(&cfg_path)?);
    tokio::spawn(wt_server::run_wt_server(
        cfg.wt_bind,
        tls.identity,
        policy,
        None,
        Some(auth_proxy),
        true,
    ));
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 1. Raw TCP (0x01) is blocked via WT
    let client = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([cert_hash.into()])
            .build(),
    )?;
    let conn = client
        .connect(format!("https://127.0.0.1:{wt_port}/"))
        .await?;
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?.await?;
    ctrl_send.write_all(&[stream_kind::CONTROL]).await?;
    let info_payload = encode_info(&InfoPayload {
        major: 2,
        minor: 1,
        extensions: vec![],
    });
    ctrl_send
        .write_all(&encode_control_frame(control_msg::INFO, &info_payload))
        .await?;
    let mut hdr = [0u8; 5];
    ctrl_recv.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
    let mut ibuf = vec![0u8; len];
    ctrl_recv.read_exact(&mut ibuf).await?;
    ctrl_recv.read_exact(&mut hdr).await?;
    let rlen = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
    let mut rbuf = vec![0u8; rlen];
    ctrl_recv.read_exact(&mut rbuf).await?;

    let (mut raw_send, mut raw_recv) = conn.open_bi().await?.await?;
    let mut raw_req = vec![stream_kind::TCP, 0x00];
    raw_req.extend_from_slice(&upstream_addr.port().to_le_bytes());
    raw_req.extend_from_slice(&9u16.to_le_bytes());
    raw_req.extend_from_slice(b"127.0.0.1");
    raw_send.write_all(&raw_req).await?;
    let mut st = [0u8; 2];
    raw_recv.read_exact(&mut st).await?;
    assert_eq!(st[0], close_reason::BLOCKED);

    // 2. HTTP_PROXY (0x02) allowed path injects secret & strips client auth
    let (mut p_send, mut p_recv) = conn.open_bi().await?.await?;
    let mut p_req = vec![stream_kind::HTTP_PROXY, 0x00];
    p_req.extend_from_slice(&3u16.to_le_bytes());
    p_req.extend_from_slice(b"api");
    p_send.write_all(&p_req).await?;
    p_recv.read_exact(&mut st).await?;
    assert_eq!(st[0], 0x00);
    p_send
        .write_all(b"GET /v1/test HTTP/1.1\r\nHost: ignored\r\nAuthorization: client-spoof\r\nConnection: close\r\n\r\n")
        .await?;
    let mut resp_buf = Vec::new();
    p_recv.read_to_end(&mut resp_buf).await?;
    let resp_str = String::from_utf8_lossy(&resp_buf);
    assert!(
        resp_str.contains("secret=true;spoof=false"),
        "got: {resp_str}"
    );

    // 3. Disallowed path returns 403
    let (mut d_send, mut d_recv) = conn.open_bi().await?.await?;
    d_send.write_all(&p_req).await?;
    d_recv.read_exact(&mut st).await?;
    assert_eq!(st[0], 0x00);
    d_send
        .write_all(b"GET /admin HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n")
        .await?;
    let mut d_buf = Vec::new();
    d_recv.read_to_end(&mut d_buf).await?;
    assert!(String::from_utf8_lossy(&d_buf).starts_with("HTTP/1.1 403"));

    // 4. 302 redirect returned raw without following
    let (mut r_send, mut r_recv) = conn.open_bi().await?.await?;
    r_send.write_all(&p_req).await?;
    r_recv.read_exact(&mut st).await?;
    assert_eq!(st[0], 0x00);
    r_send
        .write_all(b"GET /redirect HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n")
        .await?;
    let mut r_buf = Vec::new();
    r_recv.read_to_end(&mut r_buf).await?;
    assert!(String::from_utf8_lossy(&r_buf).starts_with("HTTP/1.1 302"));

    let _ = std::fs::remove_file(&cfg_path);
    Ok(())
}

#[tokio::test]
async fn ws_stream_id_replacement_safety() -> Result<()> {
    let echo_addr = spawn_tcp_echo().await?;

    let cfg = RelayConfig {
        allow_loopback: true,
        allow_any_origin: true,
        ..Default::default()
    };
    let policy = SecurityPolicy::from_config(&cfg);

    let ws_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let ws_listener = tokio::net::TcpListener::bind(ws_bind).await?;
    let ws_addr = ws_listener.local_addr()?;
    drop(ws_listener);

    tokio::spawn(async move {
        let _ =
            wisp_wt_relay::ws_server::run_ws_server(ws_addr, None, policy, None, None, false).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{ws_addr}/")).await?;
    let init = ws.next().await.unwrap()?;
    let Message::Binary(init_b) = init else {
        panic!("Expected binary CONTINUE");
    };
    assert_eq!(init_b[0], ws_pkt::CONTINUE);

    let mut connect_payload = vec![ws_stream_type::TCP];
    connect_payload.extend_from_slice(&echo_addr.port().to_le_bytes());
    connect_payload.extend_from_slice(b"127.0.0.1");

    // Open stream 1, then immediately replace stream 1 with a new CONNECT.
    ws.send(Message::Binary(
        encode_ws_packet(ws_pkt::CONNECT, 1, &connect_payload).into(),
    ))
    .await?;
    ws.send(Message::Binary(
        encode_ws_packet(ws_pkt::CONNECT, 1, &connect_payload).into(),
    ))
    .await?;

    // Give the aborted first task's StreamDropGuard time to run.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Stream 1 must still be active in the relay's map.
    ws.send(Message::Binary(
        encode_ws_packet(ws_pkt::DATA, 1, b"hello-replacement").into(),
    ))
    .await?;

    let mut echoed = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        let Some(Ok(Message::Binary(pkt))) = ws.next().await else {
            break;
        };
        if pkt.len() >= 5 && pkt[0] == ws_pkt::DATA && pkt[1..5] == 1u32.to_le_bytes() {
            echoed.extend_from_slice(&pkt[5..]);
            if echoed == b"hello-replacement" {
                break;
            }
        }
    }
    assert_eq!(echoed, b"hello-replacement");
    Ok(())
}

async fn read_ctrl(recv: &mut wtransport::RecvStream) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    recv.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await?;
    Ok((hdr[0], payload))
}

#[tokio::test]
async fn wt_udp_close_is_5_bytes() -> Result<()> {
    let closed_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let closed_port = closed_sock.local_addr()?.port();
    drop(closed_sock);

    let tls = load_or_generate_tls(None, None, true, &[])?;
    let hash_bytes = tls.cert_sha256;
    let cfg = RelayConfig {
        allow_loopback: true,
        allow_any_origin: true,
        ..Default::default()
    };
    let policy = SecurityPolicy::from_config(&cfg);

    let wt_sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let wt_addr = wt_sock.local_addr()?;
    drop(wt_sock);

    tokio::spawn(async move {
        let _ = wisp_wt_relay::wt_server::run_wt_server(
            wt_addr,
            tls.identity,
            policy,
            None,
            None,
            false,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_cfg = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash_bytes)])
        .build();
    let endpoint = wtransport::Endpoint::client(client_cfg)?;
    let conn = endpoint.connect(format!("https://{wt_addr}/")).await?;

    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?.await?;
    ctrl_send.write_all(&[stream_kind::CONTROL]).await?;
    let info_bytes = encode_info(&InfoPayload {
        major: 2,
        minor: 1,
        extensions: vec![],
    });
    ctrl_send
        .write_all(&encode_control_frame(control_msg::INFO, &info_bytes))
        .await?;
    let (msg_type, _) = read_ctrl(&mut ctrl_recv).await?;
    assert_eq!(msg_type, control_msg::INFO);
    let (msg_type, _) = read_ctrl(&mut ctrl_recv).await?;
    assert_eq!(msg_type, control_msg::READY);

    let flow_id = 7u32;
    let mut open_payload = Vec::new();
    open_payload.extend_from_slice(&flow_id.to_le_bytes());
    open_payload.extend_from_slice(&closed_port.to_le_bytes());
    open_payload.extend_from_slice(&(9u16).to_le_bytes());
    open_payload.extend_from_slice(b"127.0.0.1");
    ctrl_send
        .write_all(&encode_control_frame(control_msg::UDP_BIND, &open_payload))
        .await?;

    let (msg_type, bound_payload) = read_ctrl(&mut ctrl_recv).await?;
    assert_eq!(msg_type, control_msg::UDP_BOUND);
    assert_eq!(bound_payload.len(), 5);
    assert_eq!(bound_payload[4], 0x00);

    let mut dgram = Vec::new();
    encode_varint(flow_id as u64, &mut dgram)?;
    dgram.extend_from_slice(b"trigger-icmp");
    conn.send_datagram(dgram)?;

    let (msg_type, close_payload) =
        tokio::time::timeout(Duration::from_secs(2), read_ctrl(&mut ctrl_recv)).await??;
    assert_eq!(msg_type, control_msg::UDP_CLOSE);
    assert_eq!(close_payload.len(), 5);
    assert_eq!(
        u32::from_le_bytes(close_payload[0..4].try_into().unwrap()),
        flow_id
    );
    assert_eq!(close_payload[4], close_reason::NETWORK_ERROR);
    Ok(())
}
