import { createKernel, fetchDistro } from "unkernel/node";
import { wispWtBackend } from "../src/unkernel.ts";

const wsUrl = process.env.WISP_WS_URL ?? "ws://127.0.0.1:4434/";

async function main() {
  const distro = await fetchDistro("alpine");
  const net = wispWtBackend({
    wsUrl,
    mode: "websocket-only",
    log: (m) => console.error(m),
  });

  const vm = await createKernel({ distro, net });
  try {
    const curlRes = await vm.exec("/bin/sh", [
      "-c",
      "apk add --no-cache curl >/dev/null && curl -sI https://example.com | head -n 3",
    ]);
    console.log("curl exit:", curlRes.exitCode, "\n" + curlRes.stdout);
    if (curlRes.exitCode !== 0) {
      throw new Error(`curl failed: ${curlRes.stderr}`);
    }

    const gitRes = await vm.exec("/bin/sh", [
      "-c",
      "apk add --no-cache git >/dev/null && rm -rf /tmp/hw && git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hw && ls /tmp/hw",
    ]);
    console.log("git exit:", gitRes.exitCode, "\n" + gitRes.stdout);
    if (gitRes.exitCode !== 0) {
      throw new Error(`git clone failed: ${gitRes.stderr}`);
    }

    const parRes = await vm.exec("/bin/sh", [
      "-c",
      "apk add --no-cache nodejs npm python3 py3-pip >/dev/null && (npm install --prefix /tmp/npm-test is-odd is-even >/dev/null & pip install --break-system-packages --target /tmp/pip-test six typing-extensions >/dev/null & wait) && echo PARALLEL_OK",
    ]);
    console.log("parallel exit:", parRes.exitCode, parRes.stdout.trim());
    if (parRes.exitCode !== 0 || !parRes.stdout.includes("PARALLEL_OK")) {
      throw new Error(`parallel test failed: ${parRes.stderr}`);
    }
  } finally {
    net.close();
    await vm.stop();
  }
}

void main();
