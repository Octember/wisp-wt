import { describe, expect, test } from "bun:test";
import { WispClient } from "../src/client.ts";
import {
  CONTROL_MSG,
  WS_PKT,
  encodeControlFrame,
  encodeInfo,
  encodeWsPacket,
} from "../src/protocol.ts";
import type {
  WebSocketConstructor,
  WebSocketLike,
  WebTransportBidiStreamLike,
  WebTransportConstructor,
  WebTransportLike,
} from "../src/types.ts";

function makeMockWebTransport(opts: {
  delayMs?: number;
  failImmediate?: boolean;
}): WebTransportConstructor {
  return class MockWT implements WebTransportLike {
    readonly ready: Promise<void>;
    readonly closed = new Promise<void>(() => {});
    readonly datagrams = {
      readable: new ReadableStream<Uint8Array>({ start() {} }),
      writable: new WritableStream<Uint8Array>({ write() {} }),
      maxDatagramSize: 1200,
    };

    constructor(_url: string) {
      if (opts.failImmediate) {
        this.ready = Promise.reject(new Error("UDP/443 blocked"));
      } else {
        this.ready = new Promise((resolve) => setTimeout(resolve, opts.delayMs ?? 0));
      }
    }

    async createBidirectionalStream(): Promise<WebTransportBidiStreamLike> {
      const serverInfo = encodeControlFrame(
        CONTROL_MSG.INFO,
        encodeInfo({ major: 2, minor: 1, extensions: [] }),
      );
      const readyPayload = new Uint8Array(6);
      new DataView(readyPayload.buffer).setUint32(0, 256, true);
      new DataView(readyPayload.buffer).setUint16(4, 1200, true);
      const ready = encodeControlFrame(CONTROL_MSG.READY, readyPayload);

      let sent = false;
      const readable = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (!sent) {
            sent = true;
            controller.enqueue(serverInfo);
            controller.enqueue(ready);
          }
        },
      });
      const writable = new WritableStream<Uint8Array>({ write() {} });
      return { readable, writable };
    }

    close(): void {}
  };
}

function makeMockWebSocket(opts: { delayMs?: number } = {}): WebSocketConstructor {
  return class MockWS implements WebSocketLike {
    binaryType = "arraybuffer";
    readyState = 1;
    onopen: ((ev: unknown) => void) | null = null;
    onclose: ((ev: unknown) => void) | null = null;
    onerror: ((ev: unknown) => void) | null = null;
    onmessage: ((ev: { data: unknown }) => void) | null = null;

    constructor(_url: string) {
      setTimeout(() => {
        const credit = new Uint8Array(4);
        new DataView(credit.buffer).setUint32(0, 64, true);
        this.onmessage?.({ data: encodeWsPacket(WS_PKT.CONTINUE, 0, credit).buffer });
      }, opts.delayMs ?? 5);
    }

    send(_data: Uint8Array | ArrayBuffer): void {}
    close(): void {}
  };
}

describe("WispClient fallback & Happy Eyeballs", () => {
  test("uses WebTransport when healthy", async () => {
    const client = new WispClient({
      wtUrl: "https://relay.test/",
      wsUrl: "wss://relay.test/",
      WebTransportImpl: makeMockWebTransport({ delayMs: 5 }),
      WebSocketImpl: makeMockWebSocket({ delayMs: 20 }),
    });
    const session = await client.connect();
    expect(session.kind).toBe("webtransport");
    expect(client.stats().transport).toBe("webtransport");
    expect(client.stats().fallbackReason).toBeNull();
    client.close();
  });

  test("falls back immediately when WebTransport errors", async () => {
    const client = new WispClient({
      wtUrl: "https://relay.test/",
      wsUrl: "wss://relay.test/",
      fallbackDelayMs: 500,
      WebTransportImpl: makeMockWebTransport({ failImmediate: true }),
      WebSocketImpl: makeMockWebSocket({ delayMs: 5 }),
    });
    const session = await client.connect();
    expect(session.kind).toBe("websocket");
    expect(client.stats().fallbackReason).toContain("WebTransport failed");
    client.close();
  });

  test("falls back via Happy-Eyeballs timer when UDP/443 hangs", async () => {
    const client = new WispClient({
      wtUrl: "https://relay.test/",
      wsUrl: "wss://relay.test/",
      fallbackDelayMs: 30,
      WebTransportImpl: makeMockWebTransport({ delayMs: 5000 }),
      WebSocketImpl: makeMockWebSocket({ delayMs: 5 }),
    });
    const session = await client.connect();
    expect(session.kind).toBe("websocket");
    expect(client.stats().fallbackReason).toContain("exceeded 30ms");
    client.close();
  });

  test("respects websocket-only mode", async () => {
    const client = new WispClient({
      wtUrl: "https://relay.test/",
      wsUrl: "wss://relay.test/",
      mode: "websocket-only",
      WebTransportImpl: makeMockWebTransport({ delayMs: 1 }),
      WebSocketImpl: makeMockWebSocket({ delayMs: 5 }),
    });
    const session = await client.connect();
    expect(session.kind).toBe("websocket");
    expect(client.stats().fallbackReason).toBe("forced websocket-only");
    client.close();
  });
});
