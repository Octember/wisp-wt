// oxlint-disable promise/always-return, typescript/no-unsafe-type-assertion
import type {
  WebTransportConstructor,
  WispClientOptions,
  WispConnectionStatus,
  WispSession,
  WispSessionSnapshot,
  WispTcpStream,
  WispTcpStreamEvents,
  WispTransportKind,
  WispTransportMode,
  WispUdpFlow,
  WispUdpFlowEvents,
} from "./types.ts";
import { WispWebSocketSession } from "./ws-session.ts";
import { WispWebTransportSession } from "./wt-session.ts";

const DEFAULT_FALLBACK_DELAY_MS = 1500;
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;
const DEFAULT_UDP_BLOCKED_CACHE_MS = 60_000;

export class WispClient {
  private opts: WispClientOptions;
  private session: WispSession | null = null;
  private connectPromise: Promise<WispSession> | null = null;
  private status: WispConnectionStatus = "idle";
  private transport: WispTransportKind | null = null;
  private fallbackReason: string | null = null;
  private handshakeMs: number | null = null;
  private udpBlockedUntil = 0;

  constructor(opts: WispClientOptions) {
    this.opts = opts;
  }

  setMode(mode: WispTransportMode): void {
    if (this.opts.mode === mode) return;
    this.opts.mode = mode;
    this.udpBlockedUntil = 0;
    this.close();
  }

  updateOptions(patch: Partial<WispClientOptions>): void {
    this.opts = { ...this.opts, ...patch };
    this.udpBlockedUntil = 0;
    this.close();
  }

  stats(): WispSessionSnapshot {
    return {
      status: this.status,
      transport: this.transport,
      fallbackReason: this.fallbackReason,
      handshakeMs: this.handshakeMs,
      activeTcpStreams: this.session?.activeTcpStreams ?? 0,
      activeUdpFlows: this.session?.activeUdpFlows ?? 0,
      bytesTx: this.session?.bytesTx ?? 0,
      bytesRx: this.session?.bytesRx ?? 0,
      motd: this.session?.motd ?? null,
      maxDatagramSize: this.session?.maxDatagramSize ?? null,
    };
  }

  private emitState(): void {
    this.opts.onStateChange?.(this.stats());
  }

  async connect(): Promise<WispSession> {
    if (this.session) return this.session;
    if (this.connectPromise) return this.connectPromise;

    this.status = "connecting";
    this.emitState();

    this.connectPromise = this.establishSession().then(
      (sess) => {
        this.session = sess;
        this.status = "connected";
        this.transport = sess.kind;
        this.connectPromise = null;
        sess.onClosed(() => {
          if (this.session === sess) {
            this.session = null;
            this.status = "closed";
            this.emitState();
          }
        });
        this.emitState();
        return sess;
      },
      (err) => {
        this.connectPromise = null;
        this.status = "error";
        this.emitState();
        throw err;
      },
    );
    return this.connectPromise;
  }

  openTcpStream(host: string, port: number, events: WispTcpStreamEvents): WispTcpStream {
    if (this.session) {
      return this.session.openTcpStream(host, port, events);
    }

    let inner: WispTcpStream | null = null;
    let destroyed = false;
    let ended = false;
    let paused = false;
    const pendingWrites: Uint8Array[] = [];

    void this.connect().then(
      (sess) => {
        if (destroyed) return;
        inner = sess.openTcpStream(host, port, events);
        if (paused) inner.pause();
        for (const chunk of pendingWrites) {
          inner.write(chunk);
        }
        pendingWrites.length = 0;
        if (ended) inner.end();
      },
      (err) => {
        if (!destroyed) {
          destroyed = true;
          events.onClose(err instanceof Error ? err : new Error(String(err)));
        }
      },
    );

    return {
      write(data: Uint8Array) {
        if (destroyed) return;
        if (inner) {
          inner.write(data);
        } else {
          pendingWrites.push(data.slice());
        }
      },
      end() {
        if (destroyed || ended) return;
        ended = true;
        inner?.end();
      },
      destroy() {
        if (destroyed) return;
        destroyed = true;
        pendingWrites.length = 0;
        inner?.destroy();
      },
      pause() {
        paused = true;
        inner?.pause();
      },
      resume() {
        paused = false;
        inner?.resume();
      },
      get buffered() {
        if (inner) return inner.buffered;
        let total = 0;
        for (const c of pendingWrites) total += c.length;
        return total;
      },
    };
  }

  openUdpFlow(host: string, port: number, events: WispUdpFlowEvents): WispUdpFlow {
    if (this.session) {
      return this.session.openUdpFlow(host, port, events);
    }

    let inner: WispUdpFlow | null = null;
    let closed = false;
    const pending: Uint8Array[] = [];

    void this.connect().then(
      (sess) => {
        if (closed) return;
        inner = sess.openUdpFlow(host, port, events);
        for (const d of pending) inner.send(d);
        pending.length = 0;
      },
      (err) => {
        if (!closed) {
          closed = true;
          events.onClose(err instanceof Error ? err : new Error(String(err)));
        }
      },
    );

    return {
      flowId: 0,
      send(data: Uint8Array) {
        if (closed) return;
        if (inner) inner.send(data);
        else pending.push(data.slice());
      },
      close() {
        if (closed) return;
        closed = true;
        pending.length = 0;
        inner?.close();
      },
    };
  }

  close(): void {
    const s = this.session;
    this.session = null;
    this.connectPromise = null;
    this.status = "closed";
    s?.close();
    this.emitState();
  }

  private resolveWsUrl(): string | undefined {
    if (this.opts.wsUrl) return this.opts.wsUrl;
    if (this.opts.wtUrl) {
      return this.opts.wtUrl.replace(/^https:/i, "wss:").replace(/^http:/i, "ws:");
    }
    return undefined;
  }

  private hasWebTransport(): boolean {
    if (this.opts.WebTransportImpl) return true;
    return (
      typeof (globalThis as { WebTransport?: WebTransportConstructor }).WebTransport === "function"
    );
  }

  private async establishSession(): Promise<WispSession> {
    const t0 = performance.now();
    const mode = this.opts.mode ?? "auto";
    const wtUrl = this.opts.wtUrl;
    const wsUrl = this.resolveWsUrl();
    const log = this.opts.log ?? (() => {});
    const timeoutMs = this.opts.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
    const fallbackDelayMs = this.opts.fallbackDelayMs ?? DEFAULT_FALLBACK_DELAY_MS;
    const udpCacheMs = this.opts.udpBlockedCacheMs ?? DEFAULT_UDP_BLOCKED_CACHE_MS;

    const connectWt = () => {
      if (!wtUrl) return Promise.reject(new Error("wtUrl not configured"));
      return WispWebTransportSession.connect(wtUrl, this.opts);
    };
    const connectWs = () => {
      if (!wsUrl) return Promise.reject(new Error("wsUrl not configured"));
      return WispWebSocketSession.connect(wsUrl, this.opts);
    };

    if (mode === "websocket-only") {
      this.fallbackReason = "forced websocket-only";
      const s = await withTimeout(connectWs(), timeoutMs, "WebSocket handshake timed out");
      this.handshakeMs = Math.round(performance.now() - t0);
      log(`[wisp-wt] connected via WebSocket (${this.handshakeMs} ms)`);
      return s;
    }

    if (mode === "webtransport-only") {
      this.fallbackReason = null;
      const s = await withTimeout(connectWt(), timeoutMs, "WebTransport handshake timed out");
      this.handshakeMs = Math.round(performance.now() - t0);
      log(`[wisp-wt] connected via HTTP/3 WebTransport (${this.handshakeMs} ms)`);
      return s;
    }

    if (!this.hasWebTransport() || !wtUrl) {
      this.fallbackReason = !wtUrl ? "no wtUrl configured" : "WebTransport unsupported";
      const s = await withTimeout(connectWs(), timeoutMs, "WebSocket handshake timed out");
      this.handshakeMs = Math.round(performance.now() - t0);
      log(`[wisp-wt] fallback to WebSocket (${this.fallbackReason}, ${this.handshakeMs} ms)`);
      return s;
    }

    if (mode === "auto" && Date.now() < this.udpBlockedUntil && wsUrl) {
      this.fallbackReason = "cached UDP/443 blocked";
      const s = await withTimeout(connectWs(), timeoutMs, "WebSocket handshake timed out");
      this.handshakeMs = Math.round(performance.now() - t0);
      return s;
    }

    // Happy-Eyeballs / Race between WebTransport and WebSocket.
    const delay = mode === "race" ? 0 : fallbackDelayMs;
    return await new Promise<WispSession>((resolve, reject) => {
      let settled = false;
      let wtSession: WispSession | null = null;
      let wsSession: WispSession | null = null;
      let wtErr: Error | null = null;
      let wsErr: Error | null = null;
      let wsStarted = false;

      const finishWin = (winner: WispSession, loser: WispSession | null, reason: string | null) => {
        if (settled) {
          winner.close();
          return;
        }
        settled = true;
        clearTimeout(fallbackTimer);
        clearTimeout(overallTimer);
        loser?.close();
        this.fallbackReason = reason;
        this.handshakeMs = Math.round(performance.now() - t0);
        if (winner.kind === "websocket") {
          this.udpBlockedUntil = Date.now() + udpCacheMs;
          log(
            `[wisp-wt] fallback to WebSocket (${reason ?? "WT slower/failed"}, ${this.handshakeMs} ms)`,
          );
        } else {
          log(`[wisp-wt] connected via HTTP/3 WebTransport (${this.handshakeMs} ms)`);
        }
        resolve(winner);
      };

      const checkBothFailed = () => {
        if (!settled && wtErr && (wsErr || !wsUrl)) {
          settled = true;
          clearTimeout(fallbackTimer);
          clearTimeout(overallTimer);
          reject(wtErr);
        }
      };

      const startWs = (reason: string) => {
        if (wsStarted || settled || !wsUrl) return;
        wsStarted = true;
        connectWs().then(
          (s) => {
            wsSession = s;
            finishWin(s, wtSession, reason);
          },
          (e) => {
            wsErr = e instanceof Error ? e : new Error(String(e));
            checkBothFailed();
          },
        );
      };

      const fallbackTimer = setTimeout(() => {
        startWs(`WebTransport exceeded ${delay}ms head-start`);
      }, delay);

      const overallTimer = setTimeout(() => {
        if (settled) return;
        settled = true;
        clearTimeout(fallbackTimer);
        wtSession?.close();
        wsSession?.close();
        reject(new Error("Wisp handshake timed out"));
      }, timeoutMs);

      connectWt().then(
        (s) => {
          wtSession = s;
          finishWin(s, wsSession, null);
        },
        (e) => {
          wtErr = e instanceof Error ? e : new Error(String(e));
          if (!wsStarted && wsUrl) {
            clearTimeout(fallbackTimer);
            startWs(`WebTransport failed: ${wtErr.message}`);
          } else {
            checkBothFailed();
          }
        },
      );
    });
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}
