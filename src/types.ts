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
}

export interface WispClientOptions {
  wtUrl?: string;
  wsUrl?: string;
  mode?: WispTransportMode;
  fallbackDelayMs?: number;
  handshakeTimeoutMs?: number;
  udpBlockedCacheMs?: number;
  serverCertificateHashes?: WispServerCertificateHash[];
  authToken?: string;
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
  readonly activeTcpStreams: number;
  readonly activeUdpFlows: number;
  readonly bytesTx: number;
  readonly bytesRx: number;
  openTcpStream(host: string, port: number, events: WispTcpStreamEvents): WispTcpStream;
  openUdpFlow(host: string, port: number, events: WispUdpFlowEvents): WispUdpFlow;
  close(): void;
  onClosed(cb: (err: Error | null) => void): void;
}
