// oxlint-disable unicorn/prefer-add-event-listener, typescript/no-unsafe-type-assertion, typescript/no-unnecessary-type-assertion
import {
  EXT_ID,
  WISP_CLOSE_REASON,
  WS_PKT,
  WS_STREAM_TYPE,
  WispCloseError,
  type WispExtension,
  decodeAuthProxyRoutes,
  decodeInfo,
  encodeInfo,
  encodeWsConnectPayload,
  encodeWsPacket,
  utf8Decode,
  utf8Encode,
} from "./protocol.ts";
import type {
  AuthProxyRoute,
  WebSocketConstructor,
  WebSocketLike,
  WispClientOptions,
  WispSession,
  WispTcpStream,
  WispTcpStreamEvents,
  WispUdpFlow,
  WispUdpFlowEvents,
} from "./types.ts";

const MAX_PACKET = 64 * 1024;

interface WsStreamState {
  isUdp: boolean;
  credit: number;
  out: Uint8Array[];
  outBytes: number;
  done: boolean;
  scheduled: boolean;
  open: boolean;
  onData: (data: Uint8Array) => void;
  onEnd?: () => void;
  onDrain?: () => void;
  onClose: (err: Error | null) => void;
  pump: () => void;
}

export class WispWebSocketSession implements WispSession {
  readonly kind = "websocket" as const;
  motd: string | null = null;
  readonly maxDatagramSize: number | null = 1200;
  authProxyRoutes: AuthProxyRoute[] = [];
  activeTcpStreams = 0;
  activeUdpFlows = 0;
  bytesTx = 0;
  bytesRx = 0;

  private readonly ws: WebSocketLike;
  private initialCredit: number;
  private nextId = 1;
  private closed = false;
  private readonly streams = new Map<number, WsStreamState>();
  private readonly closeListeners: Array<(err: Error | null) => void> = [];

  private constructor(
    ws: WebSocketLike,
    initialCredit: number,
    motd: string | null,
    authProxyRoutes: AuthProxyRoute[],
  ) {
    this.ws = ws;
    this.initialCredit = initialCredit;
    this.motd = motd;
    this.authProxyRoutes = authProxyRoutes;
    this.ws.onmessage = (e) => {
      const m = toUint8Array(e.data);
      this.bytesRx += m.length;
      this.onPacket(m);
    };
    this.ws.onclose = () => {
      this.handleClosed(new Error("wisp websocket closed"));
    };
  }

  static connect(
    url: string,
    opts: Pick<WispClientOptions, "authToken" | "wispVersion" | "WebSocketImpl">,
  ): Promise<WispWebSocketSession> {
    const WS = (opts.WebSocketImpl ??
      (globalThis as { WebSocket?: WebSocketConstructor }).WebSocket) as
      | WebSocketConstructor
      | undefined;
    if (!WS) {
      return Promise.reject(new Error("WebSocket is not available in this environment"));
    }

    return new Promise<WispWebSocketSession>((resolve, reject) => {
      let settled = false;
      let motd: string | null = null;
      let authProxyRoutes: AuthProxyRoute[] = [];
      const useV2 = (opts.wispVersion ?? 2) === 2;
      const ws = useV2 ? new WS(url, ["wisp-v2"]) : new WS(url);
      ws.binaryType = "arraybuffer";

      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        try {
          ws.close();
        } catch {
          // Ignore close error.
        }
        reject(err);
      };

      ws.onerror = () => fail(new Error("WebSocket connection failed"));
      ws.onclose = () => fail(new Error("WebSocket closed during handshake"));
      ws.onmessage = (e) => {
        const m = toUint8Array(e.data);
        if (m.length < 5) return;
        const type = m[0];
        if (type === WS_PKT.INFO) {
          try {
            const info = decodeInfo(m.subarray(5));
            for (const ext of info.extensions) {
              if (ext.id === EXT_ID.MOTD) {
                motd = utf8Decode(ext.data);
              }
            }
            authProxyRoutes = decodeAuthProxyRoutes(info.extensions);
            const exts: WispExtension[] = [{ id: EXT_ID.UDP, data: new Uint8Array(0) }];
            if (opts.authToken) {
              exts.push({ id: EXT_ID.BEARER_AUTH, data: utf8Encode(opts.authToken) });
            }
            ws.send(
              encodeWsPacket(WS_PKT.INFO, 0, encodeInfo({ major: 2, minor: 1, extensions: exts })),
            );
          } catch (err) {
            fail(err instanceof Error ? err : new Error(String(err)));
          }
          return;
        }
        if (type === WS_PKT.CONTINUE && m.length >= 9) {
          settled = true;
          const credit = new DataView(m.buffer, m.byteOffset, m.byteLength).getUint32(5, true);
          resolve(new WispWebSocketSession(ws, credit, motd, authProxyRoutes));
          return;
        }
        if (type === WS_PKT.CLOSE) {
          const reason = m[5] ?? WISP_CLOSE_REASON.UNSPECIFIED;
          fail(new WispCloseError(reason));
        }
      };
    });
  }

  private onPacket(m: Uint8Array): void {
    if (m.length < 5) return;
    const dv = new DataView(m.buffer, m.byteOffset, m.byteLength);
    const id = dv.getUint32(1, true);
    const st = this.streams.get(id);
    if (!st) return;

    switch (m[0]) {
      case WS_PKT.DATA:
        st.onData(m.subarray(5));
        break;
      case WS_PKT.CONTINUE:
        if (m.length >= 9) {
          st.credit = dv.getUint32(5, true);
          st.pump();
        }
        break;
      case WS_PKT.CLOSE: {
        const reason =
          m.length > 5 ? (m[5] ?? WISP_CLOSE_REASON.UNSPECIFIED) : WISP_CLOSE_REASON.UNSPECIFIED;
        if (reason === WISP_CLOSE_REASON.VOLUNTARY) {
          st.onEnd?.();
          this.closeStream(id, null);
        } else {
          this.closeStream(id, new WispCloseError(reason));
        }
        break;
      }
    }
  }

  private trySend(pkt: Uint8Array): boolean {
    if (this.closed || this.ws.readyState !== 1) return false;
    try {
      this.ws.send(pkt);
      this.bytesTx += pkt.length;
      return true;
    } catch {
      return false;
    }
  }

  private closeStream(id: number, err: Error | null, silent = false): void {
    const st = this.streams.get(id);
    if (!st || st.done) return;
    st.done = true;
    this.streams.delete(id);
    if (st.isUdp) {
      this.activeUdpFlows = Math.max(0, this.activeUdpFlows - 1);
    } else {
      this.activeTcpStreams = Math.max(0, this.activeTcpStreams - 1);
    }
    if (!silent) {
      st.onClose(err);
    }
  }

  openTcpStream(host: string, port: number, events: WispTcpStreamEvents): WispTcpStream {
    return this.openWsStream(WS_STREAM_TYPE.TCP, host, port, events);
  }

  openHttpProxy(routeId: string, events: WispTcpStreamEvents): WispTcpStream {
    return this.openWsStream(WS_STREAM_TYPE.HTTP_PROXY, routeId, 0, events);
  }

  private openWsStream(
    streamType: number,
    host: string,
    port: number,
    events: WispTcpStreamEvents,
  ): WispTcpStream {
    const id = this.nextId++;
    this.activeTcpStreams++;

    const st: WsStreamState = {
      isUdp: false,
      credit: this.initialCredit,
      out: [],
      outBytes: 0,
      done: false,
      scheduled: false,
      open: true,
      onData: (d) => events.onData(d),
      onEnd: () => events.onEnd(),
      onDrain: () => events.onDrain(),
      onClose: (err) => events.onClose(err),
      pump: () => {
        st.scheduled = false;
        if (!st.open || st.done || this.closed) return;
        const before = st.outBytes;
        while (st.out.length > 0 && st.credit > 0) {
          let n = 0;
          let k = 0;
          while (k < st.out.length && n + st.out[k]!.length <= MAX_PACKET) {
            n += st.out[k++]!.length;
          }
          if (k === 0) {
            n = st.out[0]!.length;
            k = 1;
          }
          const pkt = new Uint8Array(5 + n);
          pkt[0] = WS_PKT.DATA;
          new DataView(pkt.buffer).setUint32(1, id, true);
          let off = 5;
          for (const chunk of st.out.splice(0, k)) {
            pkt.set(chunk, off);
            off += chunk.length;
          }
          if (!this.trySend(pkt)) break;
          st.credit--;
          st.outBytes -= n;
        }
        if (st.outBytes < before) {
          st.onDrain?.();
        }
      },
    };
    this.streams.set(id, st);

    const connectPkt = encodeWsPacket(
      WS_PKT.CONNECT,
      id,
      encodeWsConnectPayload(streamType, host, port),
    );
    this.trySend(connectPkt);
    queueMicrotask(() => {
      if (!st.done) events.onConnect();
    });

    return {
      write(data: Uint8Array) {
        if (st.done) return;
        if (data.length <= MAX_PACKET) {
          st.out.push(data.slice());
        } else {
          for (let off = 0; off < data.length; off += MAX_PACKET) {
            st.out.push(data.slice(off, Math.min(off + MAX_PACKET, data.length)));
          }
        }
        st.outBytes += data.length;
        if (!st.scheduled) {
          st.scheduled = true;
          queueMicrotask(st.pump);
        }
      },
      end() {
        // Wisp-WS has no half-close FIN; stream stays open until server or destroy().
      },
      destroy: () => {
        if (st.done) return;
        this.closeStream(id, null, true);
        if (!this.closed) {
          const pkt = encodeWsPacket(WS_PKT.CLOSE, id, Uint8Array.of(WISP_CLOSE_REASON.VOLUNTARY));
          this.trySend(pkt);
        }
      },
      pause() {},
      resume() {},
      get buffered() {
        return st.outBytes;
      },
    };
  }

  openUdpFlow(host: string, port: number, events: WispUdpFlowEvents): WispUdpFlow {
    const id = this.nextId++;
    this.activeUdpFlows++;

    const st: WsStreamState = {
      isUdp: true,
      credit: Number.POSITIVE_INFINITY,
      out: [],
      outBytes: 0,
      done: false,
      scheduled: false,
      open: true,
      onData: (d) => events.onMessage(d),
      onClose: (err) => events.onClose(err),
      pump: () => {},
    };
    this.streams.set(id, st);

    const connectPkt = encodeWsPacket(
      WS_PKT.CONNECT,
      id,
      encodeWsConnectPayload(WS_STREAM_TYPE.UDP, host, port),
    );
    this.trySend(connectPkt);
    queueMicrotask(() => {
      if (!st.done) events.onOpen?.();
    });

    return {
      flowId: id,
      send: (data: Uint8Array) => {
        if (st.done || this.closed) return;
        const pkt = encodeWsPacket(WS_PKT.DATA, id, data);
        this.trySend(pkt);
      },
      close: () => {
        if (st.done) return;
        this.closeStream(id, null);
        if (!this.closed) {
          const pkt = encodeWsPacket(WS_PKT.CLOSE, id, Uint8Array.of(WISP_CLOSE_REASON.VOLUNTARY));
          this.trySend(pkt);
        }
      },
    };
  }

  close(): void {
    this.handleClosed(null);
    try {
      this.ws.close();
    } catch {
      // Ignore already-closed socket.
    }
  }

  onClosed(cb: (err: Error | null) => void): void {
    if (this.closed) {
      cb(null);
      return;
    }
    this.closeListeners.push(cb);
  }

  private handleClosed(err: Error | null): void {
    if (this.closed) return;
    this.closed = true;
    for (const id of this.streams.keys()) {
      this.closeStream(id, err);
    }
    for (const cb of this.closeListeners) {
      cb(err);
    }
  }
}

function toUint8Array(data: unknown): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(0);
}
