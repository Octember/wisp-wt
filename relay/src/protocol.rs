use anyhow::{Result, bail};

pub mod stream_kind {
    pub const CONTROL: u8 = 0x00;
    pub const TCP: u8 = 0x01;
    pub const HTTP_PROXY: u8 = 0x02;
}

pub mod control_msg {
    pub const READY: u8 = 0x03;
    pub const CLOSE: u8 = 0x04;
    pub const INFO: u8 = 0x05;
    pub const UDP_BIND: u8 = 0x10;
    pub const UDP_BOUND: u8 = 0x11;
    pub const UDP_CLOSE: u8 = 0x12;
}

pub mod ws_pkt {
    pub const CONNECT: u8 = 0x01;
    pub const DATA: u8 = 0x02;
    pub const CONTINUE: u8 = 0x03;
    pub const CLOSE: u8 = 0x04;
    pub const INFO: u8 = 0x05;
}

pub mod ws_stream_type {
    pub const TCP: u8 = 0x01;
    pub const UDP: u8 = 0x02;
    pub const HTTP_PROXY: u8 = 0x03;
}

pub mod ext_id {
    pub const UDP: u8 = 0x01;
    pub const PASSWORD_AUTH: u8 = 0x02;
    pub const PUBKEY_AUTH: u8 = 0x03;
    pub const MOTD: u8 = 0x04;
    pub const STREAM_OPEN_CONFIRM: u8 = 0x05;
    pub const BEARER_AUTH: u8 = 0x10;
    pub const AUTH_PROXY: u8 = 0x11;
}

pub mod close_reason {
    pub const UNSPECIFIED: u8 = 0x01;
    pub const VOLUNTARY: u8 = 0x02;
    pub const NETWORK_ERROR: u8 = 0x03;
    pub const INCOMPATIBLE_EXTENSIONS: u8 = 0x04;
    pub const INVALID_INFO: u8 = 0x41;
    pub const UNREACHABLE: u8 = 0x42;
    pub const CONNECT_TIMEOUT: u8 = 0x43;
    pub const CONNECTION_REFUSED: u8 = 0x44;
    pub const TRANSFER_TIMEOUT: u8 = 0x47;
    pub const BLOCKED: u8 = 0x48;
    pub const THROTTLED: u8 = 0x49;
    pub const AUTH_INVALID_PASSWORD: u8 = 0xc0;
    pub const AUTH_REQUIRED: u8 = 0xc2;
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub id: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InfoPayload {
    pub major: u8,
    pub minor: u8,
    pub extensions: Vec<Extension>,
}

pub fn encode_info(info: &InfoPayload) -> Vec<u8> {
    let cap = 2 + info
        .extensions
        .iter()
        .map(|e| 5 + e.data.len())
        .sum::<usize>();
    let mut buf = Vec::with_capacity(cap);
    buf.push(info.major);
    buf.push(info.minor);
    for ext in &info.extensions {
        buf.push(ext.id);
        buf.extend_from_slice(&(ext.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&ext.data);
    }
    buf
}

pub fn decode_info(data: &[u8]) -> Result<InfoPayload> {
    let (&[major, minor], mut rest) = data
        .split_first_chunk::<2>()
        .ok_or_else(|| anyhow::anyhow!("INFO payload too short"))?;
    let mut extensions = Vec::new();
    while !rest.is_empty() {
        let (&[id, b0, b1, b2, b3], after_hdr) = rest
            .split_first_chunk::<5>()
            .ok_or_else(|| anyhow::anyhow!("Truncated extension header in INFO"))?;
        let len = u32::from_le_bytes([b0, b1, b2, b3]) as usize;
        let (ext_data, after_data) = after_hdr
            .split_at_checked(len)
            .ok_or_else(|| anyhow::anyhow!("Truncated extension payload in INFO"))?;
        extensions.push(Extension {
            id,
            data: ext_data.to_vec(),
        });
        rest = after_data;
    }
    Ok(InfoPayload {
        major,
        minor,
        extensions,
    })
}

pub fn encode_control_frame(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(msg_type);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub fn encode_ws_packet(pkt_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(pkt_type);
    buf.extend_from_slice(&stream_id.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// QUIC RFC 9000 variable-length integer encoder (up to 2^30 - 1 for flow IDs).
pub fn encode_varint(val: u64, out: &mut Vec<u8>) -> Result<()> {
    if val < 64 {
        out.push(val as u8);
    } else if val < 16_384 {
        let v = (val as u16) | 0x4000;
        out.extend_from_slice(&v.to_be_bytes());
    } else if val < 1_073_741_824 {
        let v = (val as u32) | 0x8000_0000;
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        bail!("varint out of supported range: {val}");
    }
    Ok(())
}

/// QUIC RFC 9000 variable-length integer decoder. Returns (value, bytes_consumed).
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize)> {
    if buf.is_empty() {
        bail!("empty varint buffer");
    }
    let first = buf[0];
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if buf.len() < len {
        bail!("truncated varint");
    }
    let mut v = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        v = (v << 8) | (b as u64);
    }
    Ok((v, len))
}

pub fn extract_token_from_info(info: &InfoPayload) -> Option<String> {
    for ext in &info.extensions {
        match ext.id {
            ext_id::BEARER_AUTH => {
                if let Ok(s) = std::str::from_utf8(&ext.data) {
                    return Some(s.to_string());
                }
            }
            ext_id::PASSWORD_AUTH if !ext.data.is_empty() => {
                let ulen = ext.data[0] as usize;
                if ulen < ext.data.len()
                    && let Ok(s) = std::str::from_utf8(&ext.data[1 + ulen..])
                {
                    return Some(s.to_string());
                }
            }
            _ => {}
        }
    }
    None
}
