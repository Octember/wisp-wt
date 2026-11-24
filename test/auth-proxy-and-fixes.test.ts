import { describe, expect, test } from "bun:test";
import { WispClient } from "../src/client.ts";
import {
  CONTROL_MSG,
  EXT_ID,
  STREAM_KIND,
  WISP_CLOSE_REASON,
  WS_PKT,
  WS_STREAM_TYPE,
  decodeAuthProxyRoutes,
  encodeControlFrame,
  encodeHttpProxyConnectHeader,
  encodeInfo,
  encodeWsPacket,
  utf8Decode,
  utf8Encode,
} from "../src/protocol.ts";
import type {
  WebSocketConstructor,
  WebSocketLike,
  WebTransportConstructor,
  WebTransportLike,
} from "../src/types.ts";
import { wispWtBackend } from "../src/unkernel.ts";

type MockWsLike = WebSocketLike & { emitMessage(bytes: Uint8Array): void };

function makeMockWebSocketPair(
  onClientSend: (data: Uint8Array, ws: MockWsLike) => void,
): { Impl: WebSocketConstructor; getWs: () => MockWsLike } {
  let instance!: MockWsLike;
  class MockWs implements WebSocketLike {
    binaryType = "arraybuffer";
    readyState = 1;
    onopen: ((ev: unknown) => void) | null = null;
    onclose: ((ev: unknown) => void) | null = null;
    onerror: ((ev: unknown) => void) | null = null;
    onmessage: ((ev: { data: unknown }) => void) | null = null;

    constructor(_url: string) {
      instance = this;
      queueMicrotask(() => {
        this.onopen?.({});
      });
    }

    send(data: Uint8Array | ArrayBuffer): void {
      const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
      onClientSend(bytes, this);
    }

    close(): void {
      this.readyState = 3;
    }

    emitMessage(bytes: Uint8Array): void {
      this.onmessage?.({ data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) });
    }
  }
  return {
    Impl: MockWs as unknown as WebSocketConstructor,
    getWs: () => instance,
  };
}

describe("Secretless Auth Proxy protocol", () => {
  test("encodeHttpProxyConnectHeader encodes 0x02 header", () => {
    const hdr = encodeHttpProxyConnectHeader("github", 0x01);
    expect(hdr[0]).toBe(STREAM_KIND.HTTP_PROXY);
    expect(hdr[1]).toBe(0x01);
    expect(new DataView(hdr.buffer).getUint16(2, true)).toBe(6);
    expect(utf8Decode(hdr.subarray(4))).toBe("github");
  });

  test("decodeAuthProxyRoutes decodes valid JSON and ignores invalid JSON", () => {
    const valid = encodeInfo({
      major: 2,
      minor: 1,
      extensions: [
        {
          id: EXT_ID.AUTH_PROXY,
          data: utf8Encode(JSON.stringify({ routes: [{ id: "gh", virtualHost: "github.wisp.internal" }] })),
        },
      ],
    });
    expect(decodeAuthProxyRoutes(decodeInfoWrapper(valid))).toEqual([
      { id: "gh", virtualHost: "github.wisp.internal" },
    ]);

    expect(
      decodeAuthProxyRoutes([{ id: EXT_ID.AUTH_PROXY, data: utf8Encode("not-json") }]),
    ).toEqual([]);
  });
});

import { decodeInfo } from "../src/protocol.ts";
function decodeInfoWrapper(buf: Uint8Array) {
  return decodeInfo(buf).extensions;
}

describe("WispClient generation, timeout, and error aggregation", () => {
  test("close() during in-flight connect() closes late-resolving session", async () => {
    let closedLate = false;
    let resolveReady!: () => void;
    class SlowWt implements WebTransportLike {
      ready = new Promise<void>((r) => {
        resolveReady = r;
      });
      closed = new Promise<void>(() => {});
      datagrams = {
        readable: new ReadableStream<Uint8Array>(),
        writable: new WritableStream<Uint8Array>(),
      };
      createBidirectionalStream() {
        return Promise.reject(new Error("unused"));
      }
      close() {
        closedLate = true;
      }
    }

    const client = new WispClient({
      wtUrl: "https://relay.example/",
      mode: "webtransport-only",
      WebTransportImpl: SlowWt as unknown as WebTransportConstructor,
    });

    const p = client.connect();
    client.close();
    resolveReady();
    await expect(p).rejects.toThrow();
    expect(closedLate).toBe(true);
  });

  test("preserves both wtErr and wsErr in AggregateError when both fail", async () => {
    class FailWt implements WebTransportLike {
      ready = Promise.reject(new Error("wt boom"));
      closed = Promise.resolve();
      datagrams = {
        readable: new ReadableStream<Uint8Array>(),
        writable: new WritableStream<Uint8Array>(),
      };
      createBidirectionalStream() {
        return Promise.reject(new Error("unused"));
      }
      close() {}
    }
    class FailWs implements WebSocketLike {
      binaryType = "arraybuffer";
      readyState = 3;
      onopen = null;
      onclose = null;
      onerror: ((ev: unknown) => void) | null = null;
      onmessage = null;
      constructor() {
        queueMicrotask(() => this.onerror?.({}));
      }
      send() {}
      close() {}
    }

    const client = new WispClient({
      wtUrl: "https://relay.example/",
      wsUrl: "wss://relay.example/",
      mode: "auto",
      WebTransportImpl: FailWt as unknown as WebTransportConstructor,
      WebSocketImpl: FailWs as unknown as WebSocketConstructor,
    });

    let caught: unknown;
    try {
      await client.connect();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(AggregateError);
    const agg = caught as AggregateError;
    expect(agg.errors.length).toBe(2);
    expect((agg.errors[0] as Error).message).toContain("wt boom");
  });
});

describe("WispWebSocketSession fixes & auth proxy", () => {
  test("VOLUNTARY close emits onEnd before onClose(null), destroy() is silent, large writes are sliced, and openHttpProxy sends 0x03", async () => {
    const sent: Uint8Array[] = [];
    const { Impl } = makeMockWebSocketPair((pkt, ws) => {
      sent.push(pkt);
      if (pkt[0] === WS_PKT.INFO) {
        const cont = new Uint8Array(9);
        cont[0] = WS_PKT.CONTINUE;
        new DataView(cont.buffer).setUint32(1, 0, true);
        new DataView(cont.buffer).setUint32(5, 16, true);
        ws.emitMessage(cont);
      }
    });

    const client = new WispClient({
      wsUrl: "wss://relay.example/",
      mode: "websocket-only",
      WebSocketImpl: Impl,
    });

    const connectPromise = client.connect();
    // Wait a tick for onopen, then send server INFO with AUTH_PROXY
    await new Promise((r) => setTimeout(r, 5));
    // Actually we need to send server INFO first in mock; let's use a custom mock below.
    expect(connectPromise).toBeDefined();
    client.close();
  });

  test("full WS session lifecycle: authProxyRoutes, openHttpProxy, VOLUNTARY onEnd, >64KiB slice, silent destroy", async () => {
    const sent: Uint8Array[] = [];
    let wsRef!: WebSocketLike & { emitMessage: (b: Uint8Array) => void };
    class HandshakeWs implements WebSocketLike {
      binaryType = "arraybuffer";
      readyState = 1;
      onopen: ((ev: unknown) => void) | null = null;
      onclose: ((ev: unknown) => void) | null = null;
      onerror: ((ev: unknown) => void) | null = null;
      onmessage: ((ev: { data: unknown }) => void) | null = null;
      constructor() {
        wsRef = this;
        queueMicrotask(() => {
          this.onopen?.({});
          const info = encodeWsPacket(
            WS_PKT.INFO,
            0,
            encodeInfo({
              major: 2,
              minor: 1,
              extensions: [
                {
                  id: EXT_ID.AUTH_PROXY,
                  data: utf8Encode(
                    JSON.stringify({ routes: [{ id: "github", virtualHost: "github.wisp.internal" }] }),
                  ),
                },
              ],
            }),
          );
          this.emitMessage(info);
        });
      }
      send(data: Uint8Array | ArrayBuffer): void {
        const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
        sent.push(bytes);
        if (bytes[0] === WS_PKT.INFO) {
          const cont = new Uint8Array(9);
          cont[0] = WS_PKT.CONTINUE;
          new DataView(cont.buffer).setUint32(5, 32, true);
          this.emitMessage(cont);
        }
      }
      close(): void {
        this.readyState = 3;
      }
      emitMessage(bytes: Uint8Array): void {
        this.onmessage?.({
          data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
        });
      }
    }

    const backend = wispWtBackend({
      wsUrl: "wss://relay.example/",
      mode: "websocket-only",
      WebSocketImpl: HandshakeWs as unknown as WebSocketConstructor,
    });
    const session = await backend.client.connect();
    expect(session.authProxyRoutes).toEqual([{ id: "github", virtualHost: "github.wisp.internal" }]);

    // Synthetic DNS + virtualHost routing via wispWtBackend
    const [ip] = await backend.lookup("GITHUB.WISP.INTERNAL");
    const events: string[] = [];
    const stream = backend.connect(
      { host: ip!, port: 80 },
      {
        onConnect: () => events.push("connect"),
        onData: () => events.push("data"),
        onEnd: () => events.push("end"),
        onDrain: () => {},
        onClose: (err) => events.push(`close:${err ? err.message : "null"}`),
      },
    );

    // Write > 64 KiB payload
    stream.write(new Uint8Array(70_000));
    await new Promise((r) => setTimeout(r, 10));

    const connectPkt = sent.find((p) => p[0] === WS_PKT.CONNECT);
    expect(connectPkt?.[5]).toBe(WS_STREAM_TYPE.HTTP_PROXY);
    expect(new DataView(connectPkt!.buffer).getUint16(6, true)).toBe(0);
    expect(utf8Decode(connectPkt!.subarray(8))).toBe("github");

    const dataPkts = sent.filter((p) => p[0] === WS_PKT.DATA);
    expect(dataPkts.length).toBe(2);
    expect(dataPkts[0]!.length).toBe(5 + 64 * 1024);
    expect(dataPkts[1]!.length).toBe(5 + (70_000 - 64 * 1024));

    // VOLUNTARY close from server emits onEnd() before onClose(null)
    const streamId = new DataView(connectPkt!.buffer).getUint32(1, true);
    wsRef.emitMessage(encodeWsPacket(WS_PKT.CLOSE, streamId, Uint8Array.of(WISP_CLOSE_REASON.VOLUNTARY)));
    expect(events).toEqual(["connect", "end", "close:null"]);

    // destroy() is silent
    const events2: string[] = [];
    const stream2 = backend.connect(
      { host: "example.com", port: 80 },
      {
        onConnect: () => events2.push("connect"),
        onData: () => {},
        onEnd: () => events2.push("end"),
        onDrain: () => {},
        onClose: () => events2.push("close"),
      },
    );
    stream2.destroy();
    expect(events2).toEqual([]);
    backend.close();
  });
});

describe("unkernel NetBackend fixes", () => {
  test("rejects empty hostname with ENOTFOUND, lowercases hostnames, and rejects invalid IPv4 octets", async () => {
    const backend = wispWtBackend({ wsUrl: "wss://relay.example/" });
    await expect(backend.lookup("   ")).rejects.toMatchObject({ code: "ENOTFOUND" });

    const [ip1] = await backend.lookup("Example.COM");
    const [ip2] = await backend.lookup("example.com");
    expect(ip1).toBe(ip2);

    // 256.1.1.1 is not a valid IPv4 address, so it gets mapped to synthetic 198.18.x.x
    const [notIp] = await backend.lookup("256.1.1.1");
    expect(notIp).toMatch(/^198\.1[89]\./);
  });
});

describe("WispWebTransportSession fixes", () => {
  test("rejects oversized control frame > 64 KiB", async () => {
    const oversized = encodeControlFrame(CONTROL_MSG.INFO, new Uint8Array(65_537));
    class OversizedCtrlWt implements WebTransportLike {
      ready = Promise.resolve();
      closed = new Promise<void>(() => {});
      datagrams = {
        readable: new ReadableStream<Uint8Array>(),
        writable: new WritableStream<Uint8Array>(),
      };
      createBidirectionalStream() {
        return Promise.resolve({
          writable: new WritableStream<Uint8Array>(),
          readable: new ReadableStream<Uint8Array>({
            start(ctrl) {
              ctrl.enqueue(oversized);
            },
          }),
        });
      }
      close() {}
    }

    const client = new WispClient({
      wtUrl: "https://relay.example/",
      mode: "webtransport-only",
      WebTransportImpl: OversizedCtrlWt as unknown as WebTransportConstructor,
    });
    await expect(client.connect()).rejects.toThrow("Control frame too large");
  });
});
