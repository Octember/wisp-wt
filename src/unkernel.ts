import { WispClient } from "./client.ts";
import type { WispClientOptions, WispSessionSnapshot, WispTransportMode } from "./types.ts";

/** Structural match for unkernel's NetConnectionEvents (js/core/net.ts). */
export interface UnkernelNetConnectionEvents {
  onConnect(): void;
  onData(data: Uint8Array): void;
  onEnd(): void;
  onDrain(): void;
  onClose(error: Error | null): void;
}

/** Structural match for unkernel's NetConnection (js/core/net.ts). */
export interface UnkernelNetConnection {
  write(data: Uint8Array): void;
  end(): void;
  destroy(): void;
  pause(): void;
  resume(): void;
  readonly buffered: number;
}

/** Structural match for unkernel's NetBackend (js/core/net.ts). */
export interface UnkernelNetBackend {
  connect(
    addr: { host: string; port: number },
    ev: UnkernelNetConnectionEvents,
  ): UnkernelNetConnection;
  lookup(name: string): Promise<string[]>;
  close?(): void;
}

export interface WispWtBackend extends UnkernelNetBackend {
  readonly client: WispClient;
  stats(): WispSessionSnapshot;
  setMode(mode: WispTransportMode): void;
  close(): void;
}

// 198.18.0.0/15 benchmark/documentation range used by unkernel's net-wisp.ts for synthetic DNS.
const FAKE_BASE = ((198 << 24) | (18 << 16)) >>> 0;
const FAKE_SIZE = 1 << 17;

const isIPv4 = (s: string): boolean => {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return false;
  return s.split(".").every((p) => Number(p) <= 255);
};
const ip4 = (s: string) => s.split(".").reduce((a, b) => ((a << 8) | Number(b)) >>> 0, 0);

/**
 * Creates a drop-in unkernel `NetBackend` backed by Wisp-over-WebTransport
 * with automatic Wisp-over-WebSocket fallback.
 */
export function wispWtBackend(options: WispClientOptions): WispWtBackend {
  const client = new WispClient(options);
  const nameToIp = new Map<string, number>();
  const ipToName = new Map<number, string>();
  let nextFake = 1;

  return {
    client,
    connect({ host, port }, ev): UnkernelNetConnection {
      const resolvedHost = isIPv4(host) ? (ipToName.get(ip4(host)) ?? host) : host.toLowerCase();
      const proxyRoute = client
        .stats()
        .authProxyRoutes.find((r) => r.virtualHost?.toLowerCase() === resolvedHost);
      if (proxyRoute) {
        return client.openHttpProxy(proxyRoute.id, ev);
      }
      return client.openTcpStream(resolvedHost, port, ev);
    },
    lookup(name: string): Promise<string[]> {
      const normalized = name.trim().toLowerCase();
      if (!normalized) {
        return Promise.reject(Object.assign(new Error("Empty hostname"), { code: "ENOTFOUND" }));
      }
      if (isIPv4(normalized)) {
        return Promise.resolve([normalized]);
      }
      let ip = nameToIp.get(normalized);
      if (ip === undefined) {
        const offset = ((nextFake - 1) % (FAKE_SIZE - 1)) + 1;
        nextFake++;
        ip = (FAKE_BASE + offset) >>> 0;
        const old = ipToName.get(ip);
        if (old !== undefined) {
          nameToIp.delete(old);
        }
        nameToIp.set(normalized, ip);
        ipToName.set(ip, normalized);
      }
      return Promise.resolve([`${ip >>> 24}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}`]);
    },
    stats() {
      return client.stats();
    },
    setMode(mode: WispTransportMode) {
      client.setMode(mode);
    },
    close() {
      client.close();
    },
  };
}
