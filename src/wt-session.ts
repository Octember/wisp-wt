// oxlint-disable typescript/no-unsafe-type-assertion, typescript/no-unnecessary-type-assertion, eslint/no-unmodified-loop-condition
import {
  CONTROL_MSG,
  EXT_ID,
  STREAM_KIND,
  WISP_CLOSE_REASON,
  WispCloseError,
  type WispExtension,
  decodeAuthProxyRoutes,
  decodeInfo,
  decodeVarint,
  encodeControlFrame,
  encodeHttpProxyConnectHeader,
  encodeInfo,
  encodeTcpConnectHeader,
  encodeUdpBindPayload,
  encodeUdpClosePayload,
  encodeVarint,
  utf8Decode,
  utf8Encode,
  varintLength,
} from "./protocol.ts";
import type {
  AuthProxyRoute,
  WebTransportConstructor,
  WebTransportLike,
  WispClientOptions,
  WispSession,
  WispTcpStream,
  WispTcpStreamEvents,
  WispUdpFlow,
  WispUdpFlowEvents,
} from "./types.ts";

interface PendingUdpBind {
  resolve: () => void;
  reject: (err: Error) => void;
}

interface ActiveUdpFlow {
  events: WispUdpFlowEvents;
  closed: boolean;
}

const MAX_CONTROL_FRAME_BYTES = 65_536;

export class WispWebTransportSession implements WispSession {
  readonly kind = "webtransport" as const;
  motd: string | null = null;
  maxDatagramSize: number | null = null;
  authProxyRoutes: AuthProxyRoute[] = [];
  activeTcpStreams = 0;
  activeUdpFlows = 0;
  bytesTx = 0;
  bytesRx = 0;

  private readonly transport: WebTransportLike;
  private ctrlWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private ctrlReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  private dgramWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private closed = false;
  private readonly closeListeners: Array<(err: Error | null) => void> = [];
  private nextFlowId = 1;
  private readonly pendingUdpBinds = new Map<number, PendingUdpBind>();
  private readonly udpFlows = new Map<number, ActiveUdpFlow>();

  private constructor(transport: WebTransportLike) {
    this.transport = transport;
  }

  static async connect(
    url: string,
    opts: Pick<WispClientOptions, "serverCertificateHashes" | "authToken" | "WebTransportImpl">,
  ): Promise<WispWebTransportSession> {
    const WT = (opts.WebTransportImpl ??
      (globalThis as { WebTransport?: WebTransportConstructor }).WebTransport) as
      | WebTransportConstructor
      | undefined;
    if (!WT) {
      throw new Error("WebTransport is not available in this environment");
    }

    const wtOpts = opts.serverCertificateHashes
      ? { serverCertificateHashes: opts.serverCertificateHashes }
      : undefined;
    const transport = new WT(url, wtOpts);
    await transport.ready;

    const session = new WispWebTransportSession(transport);
    try {
      await session.handshake(opts.authToken);
    } catch (err) {
      session.close();
      throw err;
    }
    return session;
  }

  private async handshake(authToken?: string): Promise<void> {
    const ctrl = await this.transport.createBidirectionalStream();
    this.ctrlWriter = ctrl.writable.getWriter();
    this.ctrlReader = ctrl.readable.getReader();

    const exts: WispExtension[] = [
      { id: EXT_ID.UDP, data: new Uint8Array(0) },
      { id: EXT_ID.STREAM_OPEN_CONFIRM, data: new Uint8Array(0) },
    ];
    if (authToken) {
      exts.push({ id: EXT_ID.BEARER_AUTH, data: utf8Encode(authToken) });
    }
    const infoBytes = encodeInfo({ major: 2, minor: 1, extensions: exts });
    const frame = encodeControlFrame(CONTROL_MSG.INFO, infoBytes);
    const firstPacket = new Uint8Array(1 + frame.length);
    firstPacket[0] = STREAM_KIND.CONTROL;
    firstPacket.set(frame, 1);
    await this.ctrlWriter.write(firstPacket);

    const serverInfoFrame = await this.readControlFrame();
    if (serverInfoFrame.type === CONTROL_MSG.CLOSE) {
      throw new WispCloseError(serverInfoFrame.payload[0] ?? WISP_CLOSE_REASON.UNSPECIFIED);
    }
    if (serverInfoFrame.type !== CONTROL_MSG.INFO) {
      throw new Error(`Expected SERVER_INFO (0x05), got 0x${serverInfoFrame.type.toString(16)}`);
    }
    const info = decodeInfo(serverInfoFrame.payload);
    for (const ext of info.extensions) {
      if (ext.id === EXT_ID.MOTD) {
        this.motd = utf8Decode(ext.data);
      }
    }
    this.authProxyRoutes = decodeAuthProxyRoutes(info.extensions);

    const readyFrame = await this.readControlFrame();
    if (readyFrame.type === CONTROL_MSG.CLOSE) {
      throw new WispCloseError(readyFrame.payload[0] ?? WISP_CLOSE_REASON.UNSPECIFIED);
    }
    if (readyFrame.type !== CONTROL_MSG.READY || readyFrame.payload.length < 6) {
      throw new Error(`Expected READY (0x03), got 0x${readyFrame.type.toString(16)}`);
    }
    const dv = new DataView(
      readyFrame.payload.buffer,
      readyFrame.payload.byteOffset,
      readyFrame.payload.byteLength,
    );
    const serverMaxDgram = dv.getUint16(4, true);
    const nativeMaxDgram = this.transport.datagrams.maxDatagramSize ?? serverMaxDgram;
    this.maxDatagramSize = Math.min(serverMaxDgram || 1200, nativeMaxDgram || 1200);

    void this.runControlLoop();
    void this.runDatagramLoop();
    void this.transport.closed.then(
      () => this.handleSessionClosed(null),
      (err) => this.handleSessionClosed(err instanceof Error ? err : new Error(String(err))),
    );
  }

  private async readExactFromControl(len: number): Promise<Uint8Array> {
    if (!this.ctrlReader) {
      throw new Error("Control stream closed");
    }
    const out = new Uint8Array(len);
    let offset = 0;
    while (offset < len) {
      const { value, done } = await this.ctrlReader.read();
      if (done || !value) {
        throw new Error("Control stream EOF");
      }
      const take = Math.min(value.length, len - offset);
      out.set(value.subarray(0, take), offset);
      offset += take;
      if (take < value.length) {
        // Control frames are small and sequential; buffer remainder if coalesced.
        this.ctrlRemainder = value.subarray(take);
        break;
      }
    }
    return out;
  }

  private ctrlRemainder: Uint8Array | null = null;

  private async readControlBytes(len: number): Promise<Uint8Array> {
    if (this.ctrlRemainder && this.ctrlRemainder.length > 0) {
      if (this.ctrlRemainder.length >= len) {
        const slice = this.ctrlRemainder.subarray(0, len);
        this.ctrlRemainder =
          this.ctrlRemainder.length > len ? this.ctrlRemainder.subarray(len) : null;
        return slice;
      }
      const out = new Uint8Array(len);
      out.set(this.ctrlRemainder, 0);
      const firstLen = this.ctrlRemainder.length;
      this.ctrlRemainder = null;
      const rest = await this.readExactFromControl(len - firstLen);
      out.set(rest, firstLen);
      return out;
    }
    return this.readExactFromControl(len);
  }

  private async readControlFrame(): Promise<{ type: number; payload: Uint8Array }> {
    const hdr = await this.readControlBytes(5);
    const type = hdr[0] ?? 0;
    const len = new DataView(hdr.buffer, hdr.byteOffset, hdr.byteLength).getUint32(1, true);
    if (len > MAX_CONTROL_FRAME_BYTES) {
      throw new Error(`Control frame too large: ${len} bytes`);
    }
    const payload = len > 0 ? await this.readControlBytes(len) : new Uint8Array(0);
    return { type, payload };
  }

  private async runControlLoop(): Promise<void> {
    try {
      while (!this.closed) {
        const frame = await this.readControlFrame();
        if (frame.type === CONTROL_MSG.UDP_BOUND && frame.payload.length >= 5) {
          const dv = new DataView(
            frame.payload.buffer,
            frame.payload.byteOffset,
            frame.payload.byteLength,
          );
          const flowId = dv.getUint32(0, true);
          const status = frame.payload[4] ?? WISP_CLOSE_REASON.UNSPECIFIED;
          const pending = this.pendingUdpBinds.get(flowId);
          if (pending) {
            this.pendingUdpBinds.delete(flowId);
            if (status === 0x00) {
              pending.resolve();
            } else {
              pending.reject(new WispCloseError(status));
            }
          }
        } else if (frame.type === CONTROL_MSG.UDP_CLOSE && frame.payload.length >= 5) {
          const dv = new DataView(
            frame.payload.buffer,
            frame.payload.byteOffset,
            frame.payload.byteLength,
          );
          const flowId = dv.getUint32(0, true);
          const reason = frame.payload[4] ?? WISP_CLOSE_REASON.UNSPECIFIED;
          const flow = this.udpFlows.get(flowId);
          if (flow && !flow.closed) {
            flow.closed = true;
            this.udpFlows.delete(flowId);
            this.activeUdpFlows = Math.max(0, this.activeUdpFlows - 1);
            flow.events.onClose(
              reason === WISP_CLOSE_REASON.VOLUNTARY ? null : new WispCloseError(reason),
            );
          }
        } else if (frame.type === CONTROL_MSG.CLOSE) {
          const reason = frame.payload[0] ?? WISP_CLOSE_REASON.UNSPECIFIED;
          this.handleSessionClosed(
            reason === WISP_CLOSE_REASON.VOLUNTARY ? null : new WispCloseError(reason),
          );
          break;
        }
      }
    } catch (err) {
      if (!this.closed) {
        this.handleSessionClosed(err instanceof Error ? err : new Error(String(err)));
      }
    }
  }

  private async runDatagramLoop(): Promise<void> {
    try {
      const reader = this.transport.datagrams.readable.getReader();
      while (!this.closed) {
        const { value, done } = await reader.read();
        if (done || !value) break;
        this.bytesRx += value.length;
        let flowId: number;
        let bytesRead: number;
        try {
          ({ value: flowId, bytesRead } = decodeVarint(value));
        } catch {
          continue;
        }
        const flow = this.udpFlows.get(flowId);
        if (flow && !flow.closed) {
          flow.events.onMessage(value.subarray(bytesRead));
        }
      }
    } catch {
      // Datagram loop exits when transport closes.
    }
  }

  openTcpStream(host: string, port: number, events: WispTcpStreamEvents): WispTcpStream {
    return this.openBidiStream(encodeTcpConnectHeader(host, port, 0x01), events);
  }

  openHttpProxy(routeId: string, events: WispTcpStreamEvents): WispTcpStream {
    return this.openBidiStream(encodeHttpProxyConnectHeader(routeId, 0x01), events);
  }

  private openBidiStream(hdr: Uint8Array, events: WispTcpStreamEvents): WispTcpStream {
    let done = false;
    let counted = false;
    let readEnded = false;
    let writeEnded = false;
    let paused = false;
    let resumeWaiter: (() => void) | null = null;
    let bufferedBytes = 0;
    let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    const writeQueue: Uint8Array[] = [];
    let endRequested = false;
    let pumping = false;

    const finish = (err: Error | null, silent = false) => {
      if (done) return;
      done = true;
      if (counted) {
        counted = false;
        this.activeTcpStreams = Math.max(0, this.activeTcpStreams - 1);
      }
      if (resumeWaiter) {
        const r = resumeWaiter;
        resumeWaiter = null;
        r();
      }
      if (err !== null || silent) {
        if (writer) void writer.abort().catch(() => {});
        if (reader) void reader.cancel().catch(() => {});
      }
      if (!silent) {
        events.onClose(err);
      }
    };

    const pumpWrites = async () => {
      if (pumping || !writer) return;
      pumping = true;
      try {
        while (writeQueue.length > 0 && !done) {
          const chunk = writeQueue.shift()!;
          await writer.write(chunk);
          this.bytesTx += chunk.length;
          bufferedBytes = Math.max(0, bufferedBytes - chunk.length);
          events.onDrain();
        }
        if (endRequested && !done && !writeEnded) {
          await writer.close();
          writeEnded = true;
          if (readEnded) {
            finish(null);
          }
        }
      } catch (err) {
        finish(err instanceof Error ? err : new Error(String(err)));
      } finally {
        pumping = false;
      }
    };

    void (async () => {
      try {
        if (this.closed) {
          throw new Error("WebTransport session is closed");
        }
        const bi = await this.transport.createBidirectionalStream();
        if (done) {
          void bi.writable.abort().catch(() => {});
          void bi.readable.cancel().catch(() => {});
          return;
        }
        counted = true;
        this.activeTcpStreams++;
        writer = bi.writable.getWriter();
        reader = bi.readable.getReader();

        await writer.write(hdr);
        this.bytesTx += hdr.length;

        // Read 2-byte server connect response [status, flags].
        const resp = new Uint8Array(2);
        let respPos = 0;
        let initialData: Uint8Array | null = null;
        while (respPos < 2) {
          const { value, done: rDone } = await reader.read();
          if (rDone || !value) {
            throw new Error("Stream closed before connect response");
          }
          const take = Math.min(value.length, 2 - respPos);
          resp.set(value.subarray(0, take), respPos);
          respPos += take;
          if (take < value.length) {
            initialData = value.subarray(take);
          }
        }

        const status = resp[0] ?? WISP_CLOSE_REASON.UNSPECIFIED;
        if (status !== 0x00) {
          throw new WispCloseError(status);
        }

        events.onConnect();
        if (initialData && initialData.length > 0 && !done) {
          this.bytesRx += initialData.length;
          events.onData(initialData);
        }
        void pumpWrites();

        while (!done) {
          if (paused) {
            await new Promise<void>((resolve) => {
              resumeWaiter = resolve;
            });
            if (done) break;
          }
          const { value, done: rDone } = await reader.read();
          if (rDone) {
            readEnded = true;
            events.onEnd();
            if (writeEnded) {
              finish(null);
            }
            break;
          }
          if (value && value.length > 0) {
            this.bytesRx += value.length;
            events.onData(value);
          }
        }
      } catch (err) {
        finish(err instanceof Error ? err : new Error(String(err)));
      }
    })();

    return {
      write(data: Uint8Array) {
        if (done || endRequested) return;
        const copy = data.slice();
        writeQueue.push(copy);
        bufferedBytes += copy.length;
        void pumpWrites();
      },
      end() {
        if (done || endRequested) return;
        endRequested = true;
        void pumpWrites();
      },
      destroy() {
        if (done) return;
        finish(null, true);
      },
      pause() {
        paused = true;
      },
      resume() {
        if (!paused) return;
        paused = false;
        if (resumeWaiter) {
          const r = resumeWaiter;
          resumeWaiter = null;
          r();
        }
      },
      get buffered() {
        return bufferedBytes;
      },
    };
  }

  openUdpFlow(host: string, port: number, events: WispUdpFlowEvents): WispUdpFlow {
    const flowId = this.nextFlowId++;
    const entry: ActiveUdpFlow = { events, closed: false };
    this.udpFlows.set(flowId, entry);
    this.activeUdpFlows++;

    let ready = false;
    const queued: Uint8Array[] = [];

    const sendRaw = (data: Uint8Array) => {
      if (entry.closed || this.closed) return;
      const prefix = encodeVarint(flowId);
      const maxPayload = (this.maxDatagramSize ?? 1200) - varintLength(flowId);
      if (data.length > maxPayload) {
        return;
      }
      const pkt = new Uint8Array(prefix.length + data.length);
      pkt.set(prefix, 0);
      pkt.set(data, prefix.length);
      if (!this.dgramWriter) {
        this.dgramWriter = this.transport.datagrams.writable.getWriter();
      }
      this.bytesTx += pkt.length;
      void this.dgramWriter.write(pkt).catch(() => {});
    };

    void (async () => {
      try {
        if (!this.ctrlWriter) throw new Error("Control stream closed");
        const bindPromise = new Promise<void>((resolve, reject) => {
          this.pendingUdpBinds.set(flowId, { resolve, reject });
        });
        await this.ctrlWriter.write(
          encodeControlFrame(CONTROL_MSG.UDP_BIND, encodeUdpBindPayload(flowId, host, port)),
        );
        await bindPromise;
        ready = true;
        events.onOpen?.();
        while (queued.length > 0 && !entry.closed) {
          sendRaw(queued.shift()!);
        }
      } catch (err) {
        if (!entry.closed) {
          entry.closed = true;
          this.udpFlows.delete(flowId);
          this.activeUdpFlows = Math.max(0, this.activeUdpFlows - 1);
          events.onClose(err instanceof Error ? err : new Error(String(err)));
        }
      }
    })();

    return {
      flowId,
      send(data: Uint8Array) {
        if (entry.closed) return;
        if (!ready) {
          queued.push(data.slice());
          return;
        }
        sendRaw(data);
      },
      close: () => {
        if (entry.closed) return;
        entry.closed = true;
        this.udpFlows.delete(flowId);
        this.activeUdpFlows = Math.max(0, this.activeUdpFlows - 1);
        if (this.ctrlWriter && !this.closed) {
          void this.ctrlWriter
            .write(encodeControlFrame(CONTROL_MSG.UDP_CLOSE, encodeUdpClosePayload(flowId)))
            .catch(() => {});
        }
        events.onClose(null);
      },
    };
  }

  close(): void {
    this.handleSessionClosed(null);
    try {
      this.transport.close({ closeCode: 0, reason: "client closed" });
    } catch {
      // Ignore already-closed transport.
    }
  }

  onClosed(cb: (err: Error | null) => void): void {
    if (this.closed) {
      cb(null);
      return;
    }
    this.closeListeners.push(cb);
  }

  private handleSessionClosed(err: Error | null): void {
    if (this.closed) return;
    this.closed = true;
    for (const [, pending] of this.pendingUdpBinds) {
      pending.reject(err ?? new Error("Session closed"));
    }
    this.pendingUdpBinds.clear();
    for (const [, flow] of this.udpFlows) {
      if (!flow.closed) {
        flow.closed = true;
        flow.events.onClose(err);
      }
    }
    this.udpFlows.clear();
    this.activeUdpFlows = 0;
    for (const cb of this.closeListeners) {
      cb(err);
    }
  }
}
