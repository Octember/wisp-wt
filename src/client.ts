import { getGlobalCtor, toError } from "./protocol.ts";
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
  private generation = 0;

  constructor(opts: WispClientOptions) {
    this.opts = { ...opts };
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
      authProxyRoutes: this.session?.authProxyRoutes ?? [],
    };
  }

  private emitState(): void {
    this.opts.onStateChange?.(this.stats());
  }

  async connect(): Promise<WispSession> {
    if (this.session) return this.session;
    if (this.connectPromise) return this.connectPromise;

    const gen = this.generation;
    this.status = "connecting";
    this.emitState();

    this.connectPromise = this.establishSession().then(
      (sess) => {
        if (gen !== this.generation) {
          sess.close();
          throw new Error("WispClient closed during connect");
        }
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
        if (gen === this.generation) {
          this.connectPromise = null;
          this.status = "error";
          this.emitState();
        }
        throw err;
      },
    );
    return this.connectPromise;
  }

  openTcpStream(host: string, port: number, events: WispTcpStreamEvents): WispTcpStream {
    return this.openStreamWithConnect((sess) => sess.openTcpStream(host, port, events), events);
  }

  openHttpProxy(routeId: string, events: WispTcpStreamEvents): WispTcpStream {
    return this.openStreamWithConnect((sess) => sess.openHttpProxy(routeId, events), events);
  }

  private openStreamWithConnect(
    openOnSession: (sess: WispSession) => WispTcpStream,
    events: WispTcpStreamEvents,
  ): WispTcpStream {
    if (this.session) {
      return openOnSession(this.session);
    }

    let inner: WispTcpStream | null = null;
    let destroyed = false;
    let ended = false;
    let paused = false;
    const pendingWrites: Uint8Array[] = [];

    void this.connect().then(
      (sess) => {
        if (destroyed) return;
        inner = openOnSession(sess);
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
          events.onClose(toError(err));
        }
      },
    );

    return {
      get flowId() {
        return inner?.flowId ?? 0;
      },
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
    this.generation += 1;
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
    return getGlobalCtor<WebTransportConstructor>("WebTransport") !== undefined;
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

    const connectSingle = async (
      fn: () => Promise<WispSession>,
      timeoutLabel: string,
      reason: string | null,
      logMsg?: (ms: number) => string,
    ): Promise<WispSession> => {
      this.fallbackReason = reason;
      const s = await withTimeout(fn(), timeoutMs, timeoutLabel);
      this.handshakeMs = Math.round(performance.now() - t0);
      if (logMsg) log(logMsg(this.handshakeMs));
      return s;
    };

    if (mode === "websocket-only") {
      return connectSingle(
        connectWs,
        "WebSocket handshake timed out",
        "forced websocket-only",
        (ms) => `[wisp-wt] connected via WebSocket (${ms} ms)`,
      );
    }

    if (mode === "webtransport-only") {
      return connectSingle(
        connectWt,
        "WebTransport handshake timed out",
        null,
        (ms) => `[wisp-wt] connected via HTTP/3 WebTransport (${ms} ms)`,
      );
    }

    if (!this.hasWebTransport() || !wtUrl) {
      const reason = !wtUrl ? "no wtUrl configured" : "WebTransport unsupported";
      return connectSingle(
        connectWs,
        "WebSocket handshake timed out",
        reason,
        (ms) => `[wisp-wt] fallback to WebSocket (${reason}, ${ms} ms)`,
      );
    }

    if (mode === "auto" && Date.now() < this.udpBlockedUntil && wsUrl) {
      return connectSingle(connectWs, "WebSocket handshake timed out", "cached UDP/443 blocked");
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
          if (wsErr) {
            reject(
              new AggregateError(
                [wtErr, wsErr],
                `Both WebTransport (${wtErr.message}) and WebSocket (${wsErr.message}) failed`,
              ),
            );
          } else {
            reject(wtErr);
          }
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

function withTimeout<T extends { close?: () => void }>(
  promise: Promise<T>,
  ms: number,
  message: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      reject(new Error(message));
    }, ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        if (timedOut) {
          v.close?.();
          return;
        }
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        if (timedOut) return;
        reject(e);
      },
    );
  });
}
