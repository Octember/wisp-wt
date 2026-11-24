import { describe, expect, test } from "bun:test";
import {
  EXT_ID,
  WISP_CLOSE_REASON,
  WispClient,
  WispCloseError,
  WS_PKT,
  WS_STREAM_TYPE,
  encodeInfo,
  encodeWsPacket,
  wispWtBackend,
} from "../src/index.ts";
import type { WebSocketConstructor, WebTransportConstructor } from "../src/types.ts";

describe("url shorthand & validation", () => {
  test("throws TypeError when none of url, wtUrl, wsUrl is provided", () => {
    expect(() => new WispClient({})).toThrow(TypeError);
    expect(() => wispWtBackend({})).toThrow(TypeError);
  });

  test("derives wtUrl and wsUrl from url shorthand and allows string shorthand in wispWtBackend", async () => {
    let seenWsUrl = "";
    const MockWS = class {
      readyState = 1;
      binaryType = "arraybuffer";
      onopen: (() => void) | null = null;
      onmessage: ((e: { data: unknown }) => void) | null = null;
      onerror: (() => void) | null = null;
      onclose: ((e: { code: number; reason: string }) => void) | null = null;
      constructor(url: string) {
        seenWsUrl = url;
        queueMicrotask(() => this.onerror?.());
      }
      send() {}
      close() {}
    } as unknown as WebSocketConstructor;

    const net = wispWtBackend("https://relay.example.com/");
    net.client.updateOptions({
      url: "https://relay.example.com/",
      mode: "websocket-only",
      WebSocketImpl: MockWS,
    });
    await expect(net.client.connect()).rejects.toThrow("wss://relay.example.com/");
    expect(seenWsUrl).toBe("wss://relay.example.com/");
  });
});

describe("cold-start virtualHost auth-proxy routing", () => {
  test("resolves virtualHost after connect() completes on cold start", async () => {
    const openedProxyIds: string[] = [];
    const openedTcpHosts: string[] = [];

    const MockWS = class {
      readyState = 1;
      binaryType = "arraybuffer";
      onopen: (() => void) | null = null;
      onmessage: ((e: { data: unknown }) => void) | null = null;
      onerror: (() => void) | null = null;
      onclose: ((e: { code: number; reason: string }) => void) | null = null;
      constructor() {
        queueMicrotask(() => {
          const routesJson = new TextEncoder().encode(
            JSON.stringify({ routes: [{ id: "openai", virtualHost: "api.openai.com" }] }),
          );
          const serverInfo = encodeWsPacket(
            WS_PKT.INFO,
            0,
            encodeInfo({
              major: 2,
              minor: 1,
              extensions: [{ id: EXT_ID.AUTH_PROXY, data: routesJson }],
            }),
          );
          this.onmessage?.({ data: serverInfo.buffer });
        });
      }
      send(data: Uint8Array) {
        if (data[0] === WS_PKT.INFO) {
          const confirm = encodeWsPacket(WS_PKT.CONTINUE, 0, new Uint8Array(4));
          queueMicrotask(() => this.onmessage?.({ data: confirm.buffer }));
          return;
        }
        // Inspect CONNECT packet (0x01)
        if (data[0] === WS_PKT.CONNECT) {
          const payload = data.subarray(5);
          const streamType = payload[0];
          const host = new TextDecoder().decode(payload.subarray(3));
          if (streamType === 0x03) {
            openedProxyIds.push(host);
          } else {
            openedTcpHosts.push(host);
          }
        }
      }
      close() {}
    } as unknown as WebSocketConstructor;

    const net = wispWtBackend({
      url: "https://relay.example.com/",
      mode: "websocket-only",
      WebSocketImpl: MockWS,
    });

    // Cold start: connect() has NOT been called yet.
    const stream = net.connect(
      { host: "api.openai.com", port: 443 },
      {
        onConnect: () => {},
        onData: () => {},
        onEnd: () => {},
        onClose: (err) => {
          if (err) console.error("onClose err:", err);
        },
        onDrain: () => {},
      },
    );

    await new Promise((r) => setTimeout(r, 20));
    expect(net.stats().status).toBe("connected");
    expect(openedTcpHosts).toEqual([]);
    expect(openedProxyIds).toEqual(["openai"]);
    expect(openedTcpHosts).toEqual([]);
    stream.destroy();
    net.close();
  });
});

describe("auth error fail-fast", () => {
  test("does not fall back to WebSocket when WebTransport rejects with AUTH_REQUIRED", async () => {
    let wsCalled = false;
    const MockWT = class {
      ready = Promise.reject(new WispCloseError(WISP_CLOSE_REASON.AUTH_REQUIRED));
      closed = new Promise(() => {});
      close() {}
      createBidirectionalStream() {
        return Promise.reject(new Error("unused"));
      }
    } as unknown as WebTransportConstructor;

    const MockWS = class {
      constructor() {
        wsCalled = true;
      }
    } as unknown as WebSocketConstructor;

    const client = new WispClient({
      url: "https://relay.example.com/",
      WebTransportImpl: MockWT,
      WebSocketImpl: MockWS,
    });

    await expect(client.connect()).rejects.toThrow("authentication required");
    expect(wsCalled).toBe(false);
  });
});

describe("WS ?token= query propagation", () => {
  test("appends ?token= when authToken is provided and not already in URL", async () => {
    const seenUrls: string[] = [];
    const MockWS = class {
      readyState = 1;
      binaryType = "arraybuffer";
      onerror: (() => void) | null = null;
      constructor(url: string) {
        seenUrls.push(url);
        queueMicrotask(() => this.onerror?.());
      }
      send() {}
      close() {}
    } as unknown as WebSocketConstructor;

    const client = new WispClient({
      wsUrl: "wss://relay.example.com/wisp",
      mode: "websocket-only",
      authToken: "tok+123/abc",
      WebSocketImpl: MockWS,
    });

    await expect(client.connect()).rejects.toThrow();
    expect(seenUrls[0]).toBe("wss://relay.example.com/wisp?token=tok%2B123%2Fabc");
  });
});
