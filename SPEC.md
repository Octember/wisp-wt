# Wisp-WT: WebTransport (HTTP/3) Transport Binding for Wisp

**Version:** 0.1 (aligned with Wisp v2.1)  
**Status:** Draft / Reference Implementation  
**Context:** Browser Linux networking (`unkernel`, `trynix.dev`), browser agents, and interactive systems labs.

---

## 1. Motivation

Wisp (`MercuryWorkshop/wisp-protocol`) multiplexes guest TCP and UDP connections over a single WebSocket (`wss://`). Because WebSocket runs over a single TCP connection, packet loss on any flow stalls delivery of *all* other multiplexed flows (TCP-over-TCP head-of-line blocking) and forces manual per-stream `CONTINUE` credit packets.

WebTransport (HTTP/3 over QUIC) reached cross-browser Baseline in Safari 26.4 (2026), joining Chrome/Edge and Firefox:
- Each guest TCP `CONNECT` maps to an **independent QUIC bidirectional stream**, eliminating cross-stream HoL blocking and using QUIC's native per-stream flow control (`MAX_STREAM_DATA`) instead of `CONTINUE` packets.
- Each guest UDP flow maps to **unreliable QUIC datagrams** (`transport.datagrams`) with a compact QUIC varint flow-ID prefix.
- When UDP/443 is blocked or `WebTransport` is unavailable, clients fall back automatically to Wisp-over-WebSocket (`wss://`).

---

## 2. Wire Protocol Specification

All multi-byte integers are **little-endian** (matching Wisp v1/v2), except the QUIC RFC 9000 variable-length integer used as the UDP datagram flow-ID prefix. Strings are UTF-8 without null termination.

### 2.1 Session Endpoint & Authentication

- Endpoint URL: `https://<host>:<port>/<prefix>/` (trailing slash per Wisp convention).
- Authentication tokens may be supplied via:
  1. `Authorization: Bearer <token>` HTTP/3 header (non-browser clients),
  2. `?token=<token>` query parameter, or
  3. Control Stream `INFO` extension `0x10` (Bearer Token) or `0x02` (Wisp v2 Password Auth).

### 2.2 Client-Initiated Bidirectional Stream Kind Tag

The first byte of every client-initiated QUIC bidirectional stream identifies its role:

| Kind | Meaning | Count per Session |
| :--- | :--- | :--- |
| `0x00` | **Control Stream** | Exactly 1 (opened first by client) |
| `0x01` | **Guest TCP Stream** | 1 per guest TCP connection |

### 2.3 Control Stream (`0x00`) Framing

After the leading `0x00` kind byte, messages on the Control Stream are framed as:

```text
+---------------+-------------------+-----------------------------+
| msg_type (u8) | payload_len (u32) | payload (payload_len bytes) |
+---------------+-------------------+-----------------------------+
```

#### Control Message Types

- **`0x05` `INFO`** (client → server, then server → client):
  ```text
  [major: u8 = 2][minor: u8 = 1][extensions...]
  ```
  Each extension entry uses the Wisp v2 format:
  `[ext_id: u8][ext_len: u32 LE][ext_data: ext_len bytes]`.

  Supported extension IDs:
  - `0x01` — UDP Datagrams (empty payload)
  - `0x02` — Password Auth (Wisp v2)
  - `0x03` — Public/Private Key Auth (Wisp v2)
  - `0x04` — Server MOTD (`char[]` UTF-8)
  - `0x05` — Stream Open Confirmation (empty payload)
  - `0x10` — Bearer Token Auth (`char[]` UTF-8 token)

- **`0x03` `READY`** (server → client; reuses Wisp `CONTINUE` opcode):
  ```text
  [max_concurrent_streams: u32 LE][max_datagram_payload: u16 LE]
  ```

- **`0x04` `CLOSE`** (either direction):
  ```text
  [reason: u8]
  ```
  Uses standard Wisp v2 close codes (`0x01` unspecified, `0x02` voluntary, `0x03` network error, `0x04` incompatible extensions, `0x41`–`0x49` server errors, `0x81` client error, `0xc0`–`0xc2` auth errors).

- **`0x10` `UDP_BIND`** (client → server):
  ```text
  [flow_id: u32 LE][port: u16 LE][host_len: u16 LE][host: UTF-8]
  ```

- **`0x11` `UDP_BOUND`** (server → client):
  ```text
  [flow_id: u32 LE][status: u8]
  ```
  `status == 0x00` indicates success; non-zero is a Wisp close reason.

- **`0x12` `UDP_CLOSE`** (either direction):
  ```text
  [flow_id: u32 LE][reason: u8]
  ```

### 2.4 Guest TCP Stream (`0x01`)

1. **Client → Server Handshake Header** (sent once at stream open):
   ```text
   [kind: u8 = 0x01][flags: u8][port: u16 LE][host_len: u16 LE][host: UTF-8]
   ```
   `flags` bit `0x01` requests connect confirmation (the server always sends the 2-byte response header before forwarding raw TCP bytes).

2. **Server → Client Handshake Response** (sent once after target TCP connect):
   ```text
   [status: u8][flags: u8]
   ```
   - `status == 0x00`: Target TCP socket connected; raw TCP payload follows immediately.
   - `status != 0x00`: Wisp close reason (`0x41`–`0x49`), followed by stream close/reset.

3. **Hot Path**: Zero framing after the handshake header. Raw guest TCP bytes flow directly over `stream.writable` / `stream.readable` using QUIC's native per-stream flow control.

4. **Lifecycle Mapping**:
   - Guest half-close (`end()`) → `stream.writable.close()` (QUIC FIN) → relay calls `TcpStream::shutdown()`.
   - Remote TCP FIN → relay calls `send_stream.finish()` → client `readable` ends → `onEnd()`.
   - Guest abort (`destroy()`) → `writable.abort(0x02)` + `readable.cancel(0x02)` → relay drops `TcpStream`.
   - Remote TCP RST / error → relay resets QUIC stream (`send_stream.reset(reason)`) → client fires `onClose(err)`.

### 2.5 Guest UDP Datagrams

After `UDP_BIND` / `UDP_BOUND` succeeds on the Control Stream, UDP packets are sent/received on `transport.datagrams` as:

```text
[flow_id: QUIC RFC 9000 varint (1, 2, or 4 bytes)][raw UDP payload]
```

- Flow IDs `1..63` use 1 byte; `64..16383` use 2 bytes.
- Clients enforce `maxDatagramSize - varintLen(flowId)` before sending.

---

## 3. Fallback & Resilience

1. **`auto` (Happy Eyeballs, default)**:
   - If `typeof WebTransport === "undefined"`, immediately connect via Wisp-over-WebSocket (`wss://`).
   - Otherwise, start WebTransport (`https://`) with a head-start timer (`fallbackDelayMs = 1500 ms`).
   - If WebTransport fails immediately (e.g., UDP/443 blocked or handshake error) or does not reach `READY` before `fallbackDelayMs`, start WebSocket (`wss://`) in parallel; whichever completes handshake first wins and cancels the other.
   - If WebTransport loses to WebSocket, cache `udpBlockedUntil = now + udpBlockedCacheMs` (default `60_000 ms`) so subsequent reconnects skip the head-start delay.
2. **`race`**: Start both WebTransport and WebSocket immediately; fastest handshake wins.
3. **`webtransport-only` / `websocket-only`**: Force a single transport (useful for testing and diagnostics).

---

## 4. Relay Implementation Evaluation

| Option | QUIC / HTTP/3 Stack | Strengths | Trade-offs | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Rust (`wtransport` 0.7)** | Tokio + Quinn + rustls | Zero GC pauses, predictable tail latency under datagram/stream churn, single static binary for dual-stack WT + WS (`tokio-tungstenite`), aligns with `epoxy-server` | Higher initial Rust compile time | **Selected** |
| **Go (`webtransport-go`)** | `quic-go` + `net/http` | Fast prototyping, familiar `net/http` integration | GC pressure under high-frequency datagram/stream churn | Viable alternative |
| **Node / Bun HTTP/3** | Experimental / incomplete | Same language as TS client | HTTP/3 & WebTransport server APIs not production-ready in Node 22 / Bun 1.4 | Not ready |

---

## 5. Open Questions

1. **Upstream Wisp v2 spec PR vs. standalone `wisp-wt` package?**  
   Ship standalone `@noahbuiltit/wisp-wt` first to validate cross-browser behavior (Chrome, Firefox, Safari 26.4) and `tc netem` benchmarks, then propose an upstream `transport-webtransport.md` PR to `MercuryWorkshop/wisp-protocol` reusing Wisp v2's `INFO`, extension, and close-code registries.
2. **How does `unkernel`'s `vm.connect()` / network driver interface expose pluggable transports?**  
   In `pithings/unkernel`, `vm.connect(port)` is for *inbound* host-to-guest `AF_VSOCK` streams. *Outbound* guest networking is cleanly pluggable via `createKernel({ net: NetBackend })` (`js/core/net.ts`), where `NetBackend` requires `connect({ host, port }, events): NetConnection`, `lookup(name): Promise<string[]>`, and `close?(): void`. `@noahbuiltit/wisp-wt/unkernel` implements `NetBackend` directly with zero changes to `unkernel`, upgrading `end()` (real TCP half-close) and `pause()`/`resume()` (real per-stream QUIC backpressure).
