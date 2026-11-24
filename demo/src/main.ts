import { createKernel } from "unkernel/web";
import {
  wispWtBackend,
  type WispSessionSnapshot,
  type WispTransportMode,
} from "../../src/index.ts";

interface RelayInfoResponse {
  sha256Base64: string;
  wtPort: number;
  wsPort: number;
}

function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el as T;
}

const termEl = byId<HTMLPreElement>("terminal");
const modeSelect = byId<HTMLSelectElement>("mode-select");
const hudTransport = byId<HTMLElement>("hud-transport");
const hudHandshake = byId<HTMLElement>("hud-handshake");
const hudStreams = byId<HTMLElement>("hud-streams");
const hudBytes = byId<HTMLElement>("hud-bytes");
const hudReason = byId<HTMLElement>("hud-reason");
const btnCurl = byId<HTMLButtonElement>("btn-curl");
const btnGit = byId<HTMLButtonElement>("btn-git");
const btnParallel = byId<HTMLButtonElement>("btn-parallel");
const btnClear = byId<HTMLButtonElement>("btn-clear");

function appendLog(text: string): void {
  termEl.textContent += text;
  termEl.scrollTop = termEl.scrollHeight;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

function updateHud(snap: WispSessionSnapshot): void {
  if (snap.transport === "webtransport") {
    hudTransport.textContent = "HTTP/3 WebTransport";
    hudTransport.className = "badge wt";
  } else if (snap.transport === "websocket") {
    hudTransport.textContent = "WebSocket Fallback";
    hudTransport.className = "badge ws";
  } else {
    hudTransport.textContent = snap.status;
    hudTransport.className = "badge";
  }
  hudHandshake.textContent = snap.handshakeMs !== null ? `${snap.handshakeMs} ms` : "—";
  hudStreams.textContent = `${snap.activeTcpStreams} TCP / ${snap.activeUdpFlows} UDP`;
  hudBytes.textContent = `${formatBytes(snap.bytesTx)} / ${formatBytes(snap.bytesRx)}`;
  hudReason.textContent = snap.fallbackReason ?? (snap.motd ? `MOTD: ${snap.motd}` : snap.status);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

let relayInfoRes: Response;
try {
  relayInfoRes = await fetch("/api/relay-info");
} catch (err) {
  const msg = "Relay not reachable — start with: bun run dev";
  termEl.textContent = `${msg}\n`;
  hudReason.textContent = msg;
  throw err;
}
if (!relayInfoRes.ok) {
  const msg = "Relay not reachable — start with: bun run dev";
  termEl.textContent = `${msg}\n`;
  hudReason.textContent = msg;
  const body = await relayInfoRes.text().catch(() => "");
  throw new Error(`Failed to fetch /api/relay-info (${relayInfoRes.status}): ${body}`);
}
const relayInfo = (await relayInfoRes.json()) as RelayInfoResponse;
const certHashBytes = base64ToBytes(relayInfo.sha256Base64);

const wtUrl = `https://127.0.0.1:${relayInfo.wtPort}/`;
const wsUrl = `ws://127.0.0.1:${relayInfo.wsPort}/`;

const net = wispWtBackend({
  wtUrl,
  wsUrl,
  mode: "auto",
  fallbackDelayMs: 1200,
  serverCertificateHashes: [{ algorithm: "sha-256", value: certHashBytes }],
  log: (msg) => appendLog(`${msg}\n`),
  onStateChange: updateHud,
});

const vm = await createKernel({
  distro: "/alpine.img",
  net,
});

appendLog("unkernel Alpine Linux booted!\n");
btnCurl.disabled = false;
btnGit.disabled = false;
btnParallel.disabled = false;

setInterval(() => updateHud(net.stats()), 250);

async function runShell(
  cmd: string,
): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
  appendLog(`\n$ ${cmd}\n`);
  const res = await vm.exec("/bin/sh", ["-c", cmd]);
  if (res.stdout) appendLog(res.stdout);
  if (res.stderr) appendLog(res.stderr);
  appendLog(`[exit ${String(res.exitCode)}]\n`);
  updateHud(net.stats());
  return { stdout: res.stdout, stderr: res.stderr, exitCode: res.exitCode };
}

modeSelect.addEventListener("change", () => {
  const val = modeSelect.value;
  if (val === "simulate-blocked") {
    net.client.updateOptions({
      wtUrl: "https://127.0.0.1:44399/",
      wsUrl,
      mode: "auto",
      fallbackDelayMs: 300,
    });
  } else {
    net.client.updateOptions({
      wtUrl,
      wsUrl,
      mode: val as WispTransportMode,
      fallbackDelayMs: 1200,
    });
  }
  updateHud(net.stats());
});

btnCurl.addEventListener("click", () => {
  void runShell("wget -S -O - http://example.com 2>&1 | head -n 10");
});

btnGit.addEventListener("click", () => {
  void runShell(
    "apk add --no-cache git >/dev/null && rm -rf /tmp/hw && git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hw && ls -la /tmp/hw",
  );
});

btnParallel.addEventListener("click", () => {
  void runShell(
    "apk add --no-cache nodejs npm python3 py3-pip >/dev/null && (npm install --prefix /tmp/npm-test is-odd is-even >/dev/null & pip install --break-system-packages --target /tmp/pip-test six typing-extensions >/dev/null & wait) && echo PARALLEL_OK",
  );
});

btnClear.addEventListener("click", () => {
  termEl.textContent = "";
});

(window as unknown as Record<string, unknown>).wispDemo = {
  runCommand: runShell,
  getStats: () => net.stats(),
  setMode: (m: string) => {
    modeSelect.value = m;
    modeSelect.dispatchEvent(new Event("change"));
    void net.client.connect().catch(() => {});
  },
};
