export type WispTransportKind = "webtransport" | "websocket";
export type WispTransportMode = "auto" | "race" | "webtransport-only" | "websocket-only";
export type WispConnectionStatus = "idle" | "connecting" | "connected" | "closed" | "error";

export interface WispServerCertificateHash {
  algorithm: "sha-256";
  value: Uint8Array | ArrayBuffer;
}

export interface WebTransportBidiStreamLike {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
}

export interface WebTransportDatagramsLike {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  readonly maxDatagramSize?: number;
}

export interface WebTransportLike {
  readonly ready: Promise<void>;
  readonly closed: Promise<unknown>;
  readonly datagrams: WebTransportDatagramsLike;
  createBidirectionalStream(): Promise<WebTransportBidiStreamLike>;
  close(closeInfo?: { closeCode?: number; reason?: string }): void;
}

export type WebTransportConstructor = new (
  url: string,
  options?: { serverCertificateHashes?: WispServerCertificateHash[] },
) => WebTransportLike;

export interface WebSocketLike {
  binaryType: string;
  readonly readyState: number;
  onopen: ((ev: unknown) => void) | null;
  onclose: ((ev: unknown) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  send(data: Uint8Array | ArrayBuffer): void;
  close(code?: number, reason?: string): void;
}

export type WebSocketConstructor = new (
  url: string,
  protocols?: string | string[],
) => WebSocketLike;

export interface WispTcpStreamEvents {
  onConnect(): void;
  onData(data: Uint8Array): void;
  onEnd(): void;
  onDrain(): void;
  onClose(error: Error | null): void;
}

export interface WispTcpStream {
  write(data: Uint8Array): void;
  end(): void;
  destroy(): void;
  pause(): void;
  resume(): void;
  readonly buffered: number;
}

export interface WispUdpFlowEvents {
  onOpen?(): void;
  onMessage(data: Uint8Array): void;
  onClose(error: Error | null): void;
}

export interface WispUdpFlow {
  readonly flowId: number;
  send(data: Uint8Array): void;
  close(): void;
}

/**
 * A server-advertised Secretless Auth Proxy route (`EXT_ID.AUTH_PROXY`).
 *
 * @example
 * ```ts
 * const route: AuthProxyRoute = { id: "openai", virtualHost: "api.openai.com" };
 * ```
 */
export interface AuthProxyRoute {
  /** Unique route identifier on the relay. */
  id: string;
  /** Optional virtual hostname that `wispWtBackend` maps to `openHttpProxy(id)`. */
  virtualHost?: string;
}

/**
 * Live telemetry and state snapshot for a `WispClient` session.
 *
 * @example
 * ```ts
 * const snap = client.stats();
 * console.log(snap.status, snap.transport, snap.handshakeMs);
 * ```
 */
export interface WispSessionSnapshot {
  status: WispConnectionStatus;
  transport: WispTransportKind | null;
  fallbackReason: string | null;
  handshakeMs: number | null;
  activeTcpStreams: number;
  activeUdpFlows: number;
  bytesTx: number;
  bytesRx: number;
  motd: string | null;
  maxDatagramSize: number | null;
  authProxyRoutes: readonly AuthProxyRoute[];
}

/**
 * Configuration options for {@link WispClient} and {@link wispWtBackend}.
 *
 * @example
 * ```ts
 * const client = new WispClient({
 *   url: "https://relay.example.com/",
 *   authToken: "secret-token",
 * });
 * ```
 */
export interface WispClientOptions {
  /**
   * Base relay URL shorthand. Automatically derives `wtUrl` (`https://`) and
   * `wsUrl` (`wss://` or `ws://`). Explicit `wtUrl` / `wsUrl` take precedence.
   */
  url?: string;
  /** Explicit WebTransport (HTTP/3) endpoint URL (`https://...`). */
  wtUrl?: string;
  /** Explicit WebSocket fallback endpoint URL (`wss://...` or `ws://...`). */
  wsUrl?: string;
  /**
   * Transport selection strategy.
   * @default "auto"
   */
  mode?: WispTransportMode;
  /**
   * Happy-Eyeballs delay (ms) before racing WebSocket fallback while WebTransport connects.
   * @default 350
   */
  fallbackDelayMs?: number;
  /**
   * Overall handshake timeout (ms) before failing `connect()`.
   * @default 6000
   */
  handshakeTimeoutMs?: number;
  /**
   * Duration (ms) to remember UDP/443 blockage and skip WebTransport.
   * @default 300000
   */
  udpBlockedCacheMs?: number;
  /** Self-signed certificate SHA-256 hashes for local WebTransport dev relays. */
  serverCertificateHashes?: WispServerCertificateHash[];
  /** Bearer token sent in `EXT_ID.BEARER_AUTH` (and `?token=` on WebSocket). */
  authToken?: string;
  /**
   * Wisp protocol version.
   * @default 2
   */
  wispVersion?: 1 | 2;
  log?: (msg: string) => void;
  onStateChange?: (snapshot: WispSessionSnapshot) => void;
  WebTransportImpl?: WebTransportConstructor;
  WebSocketImpl?: WebSocketConstructor;
}

export interface WispSession {
  readonly kind: WispTransportKind;
  readonly motd: string | null;
  readonly maxDatagramSize: number | null;
  readonly authProxyRoutes: readonly AuthProxyRoute[];
  readonly activeTcpStreams: number;
  readonly activeUdpFlows: number;
  readonly bytesTx: number;
  readonly bytesRx: number;
  openTcpStream(host: string, port: number, events: WispTcpStreamEvents): WispTcpStream;
  openHttpProxy(routeId: string, events: WispTcpStreamEvents): WispTcpStream;
  openUdpFlow(host: string, port: number, events: WispUdpFlowEvents): WispUdpFlow;
  close(): void;
  onClosed(cb: (err: Error | null) => void): void;
}
