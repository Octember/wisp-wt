# `wisp-wt`

**`wisp-wt` lets Linux and WebAssembly apps running in a browser tab make real network requests over HTTP/3 (WebTransport) instead of getting stuck behind WebSocket bottlenecks.**

### Why this exists

Browser tabs cannot open raw TCP or UDP sockets, so in-browser VMs and Wasm runtimes (like `unkernel`) tunnel their network traffic through a relay server. Traditionally, that tunnel is a single WebSocket (`wss://`). When one download or packet stalls on a WebSocket, every other connection in the VM freezes behind it. `wisp-wt` replaces that single-lane tunnel with **WebTransport over HTTP/3**, and automatically falls back to WebSocket if UDP is blocked on the user's network.

---

## The Payoff

### 1.9x–3.1x faster tail latency under packet loss

Measured in a Linux container with simulated packet loss (`tc netem`, ~60 ms round-trip time) running **2 concurrent 4 MiB bulk downloads + 24 interactive 4 KiB RPCs** over the same session:

| Packet Loss | Wisp-WS (WebSocket) p99 | Wisp-WT (WebTransport) p99 | Speedup |
| :--- | ---: | ---: | :--- |
| **0%** | 374.2 ms | **194.2 ms** | **1.9x faster** |
| **1%** | 643.9 ms | **237.6 ms** | **2.7x faster** |
| **2%** | 932.6 ms | **341.3 ms** | **2.7x faster** |
| **3%** | 1119.1 ms | **356.9 ms** | **3.1x faster** |

### Why? No Head-of-Line (HoL) Blocking

Think of a **WebSocket** like a single-lane highway: if one truck (a bulk download) drops a crate and stops, every sports car (API calls, SSH keystrokes, RPCs) behind it is stuck until that crate is picked up. **WebTransport** (built on HTTP/3 and QUIC) is a multi-lane highway where each connection gets its own independent lane—a dropped packet in one download never stalls your interactive requests.

### Secretless Auth Proxy

Your browser agent or guest VM can call authenticated APIs (like GitHub or OpenAI) **without ever holding your API key**. The relay injects credentials server-side on the way out, so secrets never enter browser memory or guest RAM.

---

## How It Works

```text
+-----------------------------------+          HTTP/3 (WebTransport / QUIC)          +-------------------------------+
|  Browser Tab (unkernel / Wasm)    |  ===========================================>  |  wisp-wt-relay (Rust)         |
|                                   |    Stream 1: Bulk download (4 MiB)             |                               |
|  - Guest VM / App                 |    Stream 2: Interactive RPC (4 KiB)           |  - Injects API keys (Auth     |
|  - wispWtBackend ("wisp-wt")      |    Stream 3: Auth Proxy -> GitHub API          |    Proxy)                     |
|                                   |  - - - - - - - - - - - - - - - - - - - - - ->  |  - Blocks private IPs (SSRF)  |
+-----------------------------------+    Auto-fallback to WebSocket (wss://) if      +-------------------------------+
                                         UDP/443 is blocked                                        |
                                                                                                   v
                                                                                       Real Internet / Origin APIs
```

---

## Try It in 30 Seconds

Run the local HTTP/3 + WebSocket Rust relay and the interactive Alpine Linux browser demo:

```bash
# 1. Start the local relay (self-signed TLS cert + dev /cert-hash endpoint)
cargo run --manifest-path relay/Cargo.toml --bin wisp-wt-relay -- \
  --self-signed --allow-any-origin --dev-http-bind 127.0.0.1:4435

# 2. In a second terminal, install dependencies and start the browser demo
bun install
bun run demo
```

**What you'll see:** Open the printed local URL in Chrome/Edge. The page boots Alpine Linux in `unkernel` over local WebTransport, lets you run real network commands from the browser, and includes a live **"Simulate UDP/443 blocked"** toggle to watch automatic WebSocket fallback in action.

---

## Copy-Paste `unkernel` Integration

Drop `wispWtBackend` into `unkernel` to get HTTP/3 transport, automatic WebSocket fallback, and Secretless Auth Proxy support:

```ts
import { createKernel } from "unkernel";
import { wispWtBackend } from "wisp-wt/unkernel";

const net = wispWtBackend({
  wtUrl: "https://relay.example.com/",
  wsUrl: "wss://relay.example.com/",
  mode: "auto", // WebTransport primary, automatic WebSocket fallback
});

const vm = await createKernel({ net });
```

Inside the guest VM, any Secretless Auth Proxy routes advertised by the relay (e.g. `github.wisp.internal`) are automatically mapped via internal DNS (`198.18.0.0/15`), so `curl http://github.wisp.internal/user` works with zero secrets in guest RAM.

---

## Plain-English Glossary

- **Wisp:** A lightweight protocol for multiplexing multiple TCP/UDP streams over a single browser-compatible connection.
- **WebTransport:** A modern browser API that sends data over HTTP/3 (QUIC) instead of TCP, giving each stream its own independent lane.
- **QUIC:** The UDP-based transport protocol underneath HTTP/3 that eliminates cross-stream Head-of-Line blocking and speeds up connection setup.
- **Head-of-Line (HoL) blocking:** A traffic jam where one lost packet on a shared connection stalls every other independent request behind it.
- **`unkernel`:** A browser-based Linux/Wasm runtime that uses a `NetBackend` adapter (like `wisp-wt/unkernel`) to give guest apps network access.
- **Secretless Auth Proxy:** A relay feature (`EXT_ID.AUTH_PROXY` / `0x11`) that attaches API tokens on the server so browser code and guest VMs never see your credentials.

---

## Deep Dive: Architecture, Repo Layout & Build

### Exports (`src/index.ts`)

- `wisp-wt`: `WispClient`, `WispWebTransportSession`, `WispWebSocketSession`, protocol encoders/decoders (`encodeControlFrame`, `decodeInfo`, `encodeHttpProxyConnectHeader`, etc.), and TypeScript types.
- `wisp-wt/unkernel`: `wispWtBackend` (`WispWtBackend`, `UnkernelNetBackend`).

### Repo Layout

- `src/` — Zero-dependency TypeScript client (`WispClient`, `WispWebTransportSession`, `WispWebSocketSession`) and `unkernel` adapter (`wisp-wt/unkernel`).
- `relay/` — HTTP/3 + WebSocket Rust relay (`wtransport` 0.7 + `tokio-tungstenite` 0.30) with Origin allow-listing, token auth, rate limiting, and SSRF/private-IP blocking.
- `demo/` — Interactive browser demo booting Alpine Linux via `unkernel` over local WebTransport + live UDP/443-blocked fallback toggle.
- `bench/` — Real-kernel Linux `tc netem` Docker benchmark comparing Wisp-WS vs. Wisp-WT under 0–3% packet loss ([RESULTS.md](bench/RESULTS.md)).
- `deploy/` — Production `Dockerfile.relay`, `fly.toml`, and `systemd` unit ([deploy/](deploy/)).
- `SPEC.md` — Full wire protocol specification, relay evaluation, and `unkernel` integration notes ([SPEC.md](SPEC.md)).

### Packaging & Build

```bash
bun install
bun run typecheck
bun run build
bun test
npm pack --dry-run
```
