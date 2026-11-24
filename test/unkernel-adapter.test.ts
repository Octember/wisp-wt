import { describe, expect, test } from "bun:test";
import { wispWtBackend } from "../src/unkernel.ts";

describe("unkernel NetBackend adapter", () => {
  test("maps hostnames to stable 198.18.0.0/15 synthetic IPs and passes IPv4 through", async () => {
    const backend = wispWtBackend({
      wtUrl: "https://relay.test/",
      mode: "websocket-only",
    });

    const ips1 = await backend.lookup("example.com");
    const ips2 = await backend.lookup("example.com");
    expect(ips1).toEqual(ips2);
    expect(ips1[0]?.startsWith("198.18.") || ips1[0]?.startsWith("198.19.")).toBe(true);

    const direct = await backend.lookup("1.1.1.1");
    expect(direct).toEqual(["1.1.1.1"]);

    backend.close();
  });
});
