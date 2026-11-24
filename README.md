# `wisp-wt`

WebTransport (HTTP/3) transport binding for [Wisp](https://github.com/MercuryWorkshop/wisp-protocol), with automatic Happy-Eyeballs fallback to Wisp-over-WebSocket (`wss://`), a dual-stack Rust relay (`wisp-wt-relay`), and a drop-in `unkernel` `NetBackend` adapter.

## Layout

- `src/` — Zero-dependency TypeScript client (`WispClient`, `WispWebTransportSession`, `WispWebSocketSession`) and `unkernel` adapter (`wisp-wt/unkernel`).
- `relay/` — Dual-stack Rust relay (`wtransport` 0.7 HTTP/3 + `tokio-tungstenite` 0.30 WebSocket) with Origin allow-listing, token auth, rate limiting, and SSRF/private-IP blocking.
- `demo/` — Interactive browser demo booting Alpine Linux via `unkernel` over local WebTransport + live UDP/443-blocked fallback toggle.
- `bench/` — Real-kernel Linux `tc netem` Docker benchmark comparing Wisp-WS vs. Wisp-WT under 0–3% packet loss ([RESULTS.md](bench/RESULTS.md)).
- `deploy/` — Production `Dockerfile.relay`, `fly.toml`, and `systemd` unit.
- `SPEC.md` — Full wire protocol specification, relay evaluation, and `unkernel` integration notes.

## Quick Start

```bash
# 1. Start the local dual-stack relay (self-signed ECDSA P-256 cert + dev /cert-hash endpoint)
cargo run --manifest-path relay/Cargo.toml --bin wisp-wt-relay -- \
  --self-signed --allow-any-origin --dev-http-bind 127.0.0.1:4435

# 2. Start the unkernel browser demo
bun install
bun run demo
```

## Usage with `unkernel`

```ts
import { createKernel } from "unkernel";
import { wispWtBackend } from "wisp-wt/unkernel";

const net = wispWtBackend({
  wtUrl: "https://relay.example.com/",
  wsUrl: "wss://relay.example.com/",
  mode: "auto", // WebTransport primary, automatic WS fallback
});

const vm = await createKernel({ net });
```
