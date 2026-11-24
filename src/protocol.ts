const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const STREAM_KIND = {
  CONTROL: 0x00,
  TCP: 0x01,
} as const;

export const CONTROL_MSG = {
  READY: 0x03,
  CLOSE: 0x04,
  INFO: 0x05,
  UDP_BIND: 0x10,
  UDP_BOUND: 0x11,
  UDP_CLOSE: 0x12,
} as const;

export const WS_PKT = {
  CONNECT: 0x01,
  DATA: 0x02,
  CONTINUE: 0x03,
  CLOSE: 0x04,
  INFO: 0x05,
} as const;

export const WS_STREAM_TYPE = {
  TCP: 0x01,
  UDP: 0x02,
} as const;

export const EXT_ID = {
  UDP: 0x01,
  PASSWORD_AUTH: 0x02,
  PUBKEY_AUTH: 0x03,
  MOTD: 0x04,
  STREAM_OPEN_CONFIRM: 0x05,
  BEARER_AUTH: 0x10,
} as const;

export const WISP_CLOSE_REASON = {
  UNSPECIFIED: 0x01,
  VOLUNTARY: 0x02,
  NETWORK_ERROR: 0x03,
  INCOMPATIBLE_EXTENSIONS: 0x04,
  INVALID_INFO: 0x41,
  UNREACHABLE: 0x42,
  CONNECT_TIMEOUT: 0x43,
  CONNECTION_REFUSED: 0x44,
  TRANSFER_TIMEOUT: 0x47,
  BLOCKED: 0x48,
  THROTTLED: 0x49,
  CLIENT_ERROR: 0x81,
  AUTH_INVALID_PASSWORD: 0xc0,
  AUTH_INVALID_SIGNATURE: 0xc1,
  AUTH_REQUIRED: 0xc2,
} as const;

const CLOSE_REASON_LABELS: Record<number, string> = {
  [WISP_CLOSE_REASON.UNSPECIFIED]: "unspecified",
  [WISP_CLOSE_REASON.VOLUNTARY]: "voluntary close",
  [WISP_CLOSE_REASON.NETWORK_ERROR]: "network error",
  [WISP_CLOSE_REASON.INCOMPATIBLE_EXTENSIONS]: "incompatible extensions",
  [WISP_CLOSE_REASON.INVALID_INFO]: "invalid destination info",
  [WISP_CLOSE_REASON.UNREACHABLE]: "host unreachable",
  [WISP_CLOSE_REASON.CONNECT_TIMEOUT]: "connect timed out",
  [WISP_CLOSE_REASON.CONNECTION_REFUSED]: "connection refused",
  [WISP_CLOSE_REASON.TRANSFER_TIMEOUT]: "transfer timed out",
  [WISP_CLOSE_REASON.BLOCKED]: "blocked by relay policy",
  [WISP_CLOSE_REASON.THROTTLED]: "throttled by relay",
  [WISP_CLOSE_REASON.CLIENT_ERROR]: "client error",
  [WISP_CLOSE_REASON.AUTH_INVALID_PASSWORD]: "invalid credentials",
  [WISP_CLOSE_REASON.AUTH_INVALID_SIGNATURE]: "invalid signature",
  [WISP_CLOSE_REASON.AUTH_REQUIRED]: "authentication required",
};

export function describeCloseReason(reason: number): string {
  return CLOSE_REASON_LABELS[reason] ?? `close reason 0x${reason.toString(16)}`;
}

export class WispCloseError extends Error {
  readonly reason: number;

  constructor(reason: number, prefix = "wisp") {
    super(`${prefix}: ${describeCloseReason(reason)}`);
    this.name = "WispCloseError";
    this.reason = reason;
  }
}

export interface WispExtension {
  id: number;
  data: Uint8Array;
}

export interface WispInfoPayload {
  major: number;
  minor: number;
  extensions: WispExtension[];
}

export function encodeInfo(info: WispInfoPayload): Uint8Array {
  let extBytes = 0;
  for (const ext of info.extensions) {
    extBytes += 5 + ext.data.length;
  }
  const out = new Uint8Array(2 + extBytes);
  const dv = new DataView(out.buffer);
  out[0] = info.major;
  out[1] = info.minor;
  let pos = 2;
  for (const ext of info.extensions) {
    out[pos] = ext.id;
    dv.setUint32(pos + 1, ext.data.length, true);
    out.set(ext.data, pos + 5);
    pos += 5 + ext.data.length;
  }
  return out;
}

export function decodeInfo(buf: Uint8Array): WispInfoPayload {
  if (buf.length < 2) {
    throw new Error("INFO payload too short");
  }
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const major = buf[0] ?? 0;
  const minor = buf[1] ?? 0;
  let pos = 2;
  const extensions: WispExtension[] = [];
  while (pos < buf.length) {
    if (pos + 5 > buf.length) {
      throw new Error("Truncated extension header in INFO");
    }
    const id = buf[pos] ?? 0;
    const len = dv.getUint32(pos + 1, true);
    pos += 5;
    if (pos + len > buf.length) {
      throw new Error("Truncated extension payload in INFO");
    }
    extensions.push({ id, data: buf.subarray(pos, pos + len) });
    pos += len;
  }
  return { major, minor, extensions };
}

export function encodeControlFrame(msgType: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + payload.length);
  out[0] = msgType;
  new DataView(out.buffer).setUint32(1, payload.length, true);
  out.set(payload, 5);
  return out;
}

export function encodeTcpConnectHeader(host: string, port: number, flags = 0x01): Uint8Array {
  const hostBytes = textEncoder.encode(host);
  const out = new Uint8Array(6 + hostBytes.length);
  const dv = new DataView(out.buffer);
  out[0] = STREAM_KIND.TCP;
  out[1] = flags;
  dv.setUint16(2, port, true);
  dv.setUint16(4, hostBytes.length, true);
  out.set(hostBytes, 6);
  return out;
}

export function encodeUdpBindPayload(flowId: number, host: string, port: number): Uint8Array {
  const hostBytes = textEncoder.encode(host);
  const out = new Uint8Array(8 + hostBytes.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, flowId, true);
  dv.setUint16(4, port, true);
  dv.setUint16(6, hostBytes.length, true);
  out.set(hostBytes, 8);
  return out;
}

export function encodeUdpClosePayload(
  flowId: number,
  reason = WISP_CLOSE_REASON.VOLUNTARY,
): Uint8Array {
  const out = new Uint8Array(5);
  new DataView(out.buffer).setUint32(0, flowId, true);
  out[4] = reason;
  return out;
}

export function encodeWsPacket(
  pktType: number,
  streamId: number,
  payload?: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(5 + (payload?.length ?? 0));
  out[0] = pktType;
  new DataView(out.buffer).setUint32(1, streamId, true);
  if (payload) {
    out.set(payload, 5);
  }
  return out;
}

export function encodeWsConnectPayload(streamType: number, host: string, port: number): Uint8Array {
  const hostBytes = textEncoder.encode(host);
  const out = new Uint8Array(3 + hostBytes.length);
  out[0] = streamType;
  new DataView(out.buffer).setUint16(1, port, true);
  out.set(hostBytes, 3);
  return out;
}

export function varintLength(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value >= 1_073_741_824) {
    throw new RangeError(`QUIC varint out of supported range: ${value}`);
  }
  if (value < 64) return 1;
  if (value < 16_384) return 2;
  return 4;
}

export function encodeVarint(value: number): Uint8Array {
  const len = varintLength(value);
  const out = new Uint8Array(len);
  const dv = new DataView(out.buffer);
  if (len === 1) {
    out[0] = value;
  } else if (len === 2) {
    dv.setUint16(0, value | 0x4000, false);
  } else {
    dv.setUint32(0, (value | 0x8000_0000) >>> 0, false);
  }
  return out;
}

export function decodeVarint(buf: Uint8Array, offset = 0): { value: number; bytesRead: number } {
  if (offset >= buf.length) {
    throw new Error("Empty varint buffer");
  }
  const first = buf[offset] ?? 0;
  const len = 1 << (first >> 6);
  if (offset + len > buf.length) {
    throw new Error("Truncated varint");
  }
  let value = first & 0x3f;
  for (let i = 1; i < len; i++) {
    value = value * 256 + (buf[offset + i] ?? 0);
  }
  return { value, bytesRead: len };
}

export function utf8Decode(buf: Uint8Array): string {
  return textDecoder.decode(buf);
}

export function utf8Encode(text: string): Uint8Array {
  return textEncoder.encode(text);
}
