#!/usr/bin/env bun

import { spawn, type Subprocess } from "bun";

const RELAY_CERT_HASH_URL = "http://127.0.0.1:4435/cert-hash";
const DEMO_PORT = process.env.PORT ?? process.env.DEMO_PORT ?? "4173";
const extraRelayArgs = process.argv.slice(2);

let relayProc: Subprocess | null = null;
let demoProc: Subprocess | null = null;
let shuttingDown = false;

function shutdown(signal: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n[dev] received ${signal}, shutting down...`);
  try {
    demoProc?.kill();
  } catch {
    // ignore
  }
  try {
    relayProc?.kill();
  } catch {
    // ignore
  }
  process.exit(0);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

async function waitForRelay(timeoutMs = 120_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (relayProc && relayProc.exitCode !== null) {
      throw new Error(`wisp-wt-relay exited early with code ${relayProc.exitCode}`);
    }
    try {
      const res = await fetch(RELAY_CERT_HASH_URL);
      if (res.ok) return;
    } catch {
      // still starting
    }
    await Bun.sleep(250);
  }
  throw new Error(`Timed out waiting for relay at ${RELAY_CERT_HASH_URL}`);
}

console.log("[dev] starting wisp-wt-relay --dev...");
relayProc = spawn(["cargo", "run", "--manifest-path", "relay/Cargo.toml", "--", "--dev", ...extraRelayArgs], {
  stdout: "inherit",
  stderr: "inherit",
});

await waitForRelay();

console.log("[dev] starting demo server...");
demoProc = spawn(["bun", "demo/server.ts"], {
  stdout: "inherit",
  stderr: "inherit",
  env: { ...process.env, PORT: DEMO_PORT },
});

console.log("");
console.log("  wisp-wt local dev ready");
console.log(`  Demo:       http://127.0.0.1:${DEMO_PORT}`);
console.log(`  Relay info: ${RELAY_CERT_HASH_URL}`);
console.log("  Press Ctrl+C to stop both processes.");
console.log("");

await Promise.race([
  relayProc.exited.then((code) => {
    if (!shuttingDown) {
      console.error(`[dev] relay exited with code ${code}`);
      shutdown("relay-exit");
    }
  }),
  demoProc.exited.then((code) => {
    if (!shuttingDown) {
      console.error(`[dev] demo exited with code ${code}`);
      shutdown("demo-exit");
    }
  }),
]);
