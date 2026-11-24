import { describe, expect, test } from "bun:test";
import {
  CONTROL_MSG,
  EXT_ID,
  STREAM_KIND,
  WISP_CLOSE_REASON,
  WS_PKT,
  WS_STREAM_TYPE,
  WispCloseError,
  decodeInfo,
  decodeVarint,
  describeCloseReason,
  encodeControlFrame,
  encodeInfo,
  encodeTcpConnectHeader,
  encodeUdpBindPayload,
  encodeUdpClosePayload,
  encodeVarint,
  encodeWsConnectPayload,
  encodeWsPacket,
  varintLength,
} from "../src/protocol.ts";

describe("QUIC varint", () => {
  test("encodes and decodes boundary values", () => {
    const cases = [0, 1, 63, 64, 16383, 16384, 1_073_741_823];
    for (const val of cases) {
      const encoded = encodeVarint(val);
      expect(encoded.length).toBe(varintLength(val));
      const decoded = decodeVarint(encoded);
      expect(decoded.value).toBe(val);
      expect(decoded.bytesRead).toBe(encoded.length);
    }
  });

  test("rejects out of range varint", () => {
    expect(() => encodeVarint(-1)).toThrow();
    expect(() => encodeVarint(1_073_741_824)).toThrow();
  });
});

describe("Wisp-WT binary codecs", () => {
  test("encodes and decodes INFO with extensions", () => {
    const token = new TextEncoder().encode("secret-token");
    const raw = encodeInfo({
      major: 2,
      minor: 1,
      extensions: [
        { id: EXT_ID.UDP, data: new Uint8Array(0) },
        { id: EXT_ID.BEARER_AUTH, data: token },
      ],
    });
    const decoded = decodeInfo(raw);
    expect(decoded.major).toBe(2);
    expect(decoded.minor).toBe(1);
    expect(decoded.extensions.length).toBe(2);
    expect(decoded.extensions[0]?.id).toBe(EXT_ID.UDP);
    expect(decoded.extensions[1]?.id).toBe(EXT_ID.BEARER_AUTH);
    expect(new TextDecoder().decode(decoded.extensions[1]?.data)).toBe("secret-token");
  });

  test("encodes control frame and TCP connect header", () => {
    const frame = encodeControlFrame(CONTROL_MSG.READY, Uint8Array.of(1, 2, 3));
    expect(frame[0]).toBe(CONTROL_MSG.READY);
    expect(new DataView(frame.buffer).getUint32(1, true)).toBe(3);

    const tcp = encodeTcpConnectHeader("example.com", 443, 0x01);
    expect(tcp[0]).toBe(STREAM_KIND.TCP);
    expect(tcp[1]).toBe(0x01);
    const dv = new DataView(tcp.buffer);
    expect(dv.getUint16(2, true)).toBe(443);
    expect(dv.getUint16(4, true)).toBe(11);
    expect(new TextDecoder().decode(tcp.subarray(6))).toBe("example.com");
  });

  test("encodes UDP bind/close and WS packets", () => {
    const bind = encodeUdpBindPayload(7, "1.1.1.1", 53);
    const dv = new DataView(bind.buffer);
    expect(dv.getUint32(0, true)).toBe(7);
    expect(dv.getUint16(4, true)).toBe(53);
    expect(dv.getUint16(6, true)).toBe(7);

    const close = encodeUdpClosePayload(7, WISP_CLOSE_REASON.VOLUNTARY);
    expect(close.length).toBe(5);
    expect(close[4]).toBe(WISP_CLOSE_REASON.VOLUNTARY);

    const ws = encodeWsPacket(
      WS_PKT.CONNECT,
      42,
      encodeWsConnectPayload(WS_STREAM_TYPE.TCP, "a.io", 80),
    );
    expect(ws[0]).toBe(WS_PKT.CONNECT);
    expect(new DataView(ws.buffer).getUint32(1, true)).toBe(42);
    expect(ws[5]).toBe(WS_STREAM_TYPE.TCP);
  });

  test("describes close reasons", () => {
    const err = new WispCloseError(WISP_CLOSE_REASON.BLOCKED);
    expect(err.reason).toBe(WISP_CLOSE_REASON.BLOCKED);
    expect(describeCloseReason(WISP_CLOSE_REASON.CONNECTION_REFUSED)).toBe("connection refused");
  });
});
