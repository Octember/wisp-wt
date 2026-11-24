import { createKernel, fetchDistro } from "unkernel/node";
import { wispWtBackend } from "../src/unkernel.ts";

const spawnRelayFlag = process.argv.includes("--spawn-relay");
const envWsUrl = process.env.WISP_WS_URL;

async function startRelay(wsPort: number, wtPort: number) {
  const proc = Bun.spawn(
    [
      "cargo",
      "run",
      "--manifest-path",
      "relay/Cargo.toml",
      "--bin",
      "wisp-wt-relay",
      "--",
      "--self-signed",
      "--allow-any-origin",
      "--ws-bind",
      `127.0.0.1:${wsPort}`,
      "--wt-bind",
      `127.0.0.1:${wtPort}`,
    ],
    { stdout: "ignore", stderr: "inherit" },
  );
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const ws = new WebSocket(`ws://127.0.0.1:${wsPort}/`);
      await new Promise<void>((resolve, reject) => {
        ws.onopen = () => {
          ws.close();
          resolve();
        };
        ws.onerror = () => reject(new Error("not ready"));
      });
      return proc;
    } catch {
      await Bun.sleep(250);
    }
  }
  proc.kill();
  throw new Error("Timed out waiting for wisp-wt-relay to start");
}

async function main() {
  let relayProc: ReturnType<typeof Bun.spawn> | null = null;
  let wsUrl = envWsUrl ?? "ws://127.0.0.1:4434/";

  if (spawnRelayFlag || !envWsUrl) {
    const wsPort = 14434;
    const wtPort = 14433;
    relayProc = await startRelay(wsPort, wtPort);
    wsUrl = `ws://127.0.0.1:${wsPort}/`;
  }

  try {
    const distro = await fetchDistro("alpine");
    const net = wispWtBackend({
      wsUrl,
      mode: "websocket-only",
      log: (m) => console.error(m),
    });

    const vm = await createKernel({ distro, net });
    try {
      const wgetRes = await vm.exec("/bin/sh", [
        "-c",
        "wget -S -O - http://example.com 2>&1 | head -n 10",
      ]);
      console.log("wget exit:", wgetRes.exitCode, "\n" + wgetRes.stdout);
      if (wgetRes.exitCode !== 0 || !wgetRes.stdout.includes("HTTP/")) {
        throw new Error(`wget failed: ${wgetRes.stderr}`);
      }
    } finally {
      net.close();
      await vm.stop();
    }
  } finally {
    relayProc?.kill();
  }
}

void main();
