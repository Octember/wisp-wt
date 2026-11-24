import { join, resolve } from "node:path";
import { fetchDistro } from "unkernel/node";

const DEMO_DIR = resolve(import.meta.dir);
const PKG_DIR = resolve(DEMO_DIR, "..");
const PORT = Number(process.env.DEMO_PORT ?? "4173");
const RELAY_INFO_URL = process.env.RELAY_INFO_URL ?? "http://127.0.0.1:4435/cert-hash";

const COOP_COEP_HEADERS: Record<string, string> = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
};

async function buildClientBundle(): Promise<string> {
  const result = await Bun.build({
    entrypoints: [join(DEMO_DIR, "src/main.ts")],
    outdir: join(DEMO_DIR, "dist"),
    target: "browser",
    format: "esm",
    splitting: false,
    sourcemap: "inline",
  });
  if (!result.success) {
    const msgs = result.logs.map((l) => l.message).join("\n");
    throw new Error(`Failed to bundle demo/src/main.ts:\n${msgs}`);
  }
  return await Bun.file(join(DEMO_DIR, "dist/main.js")).text();
}

const bundledJs = await buildClientBundle();
const alpinePath = await fetchDistro("alpine");

function resolveUnkernelAsset(filename: string): string {
  const local = join(PKG_DIR, "node_modules/unkernel/dist", filename);
  return local;
}

const server = Bun.serve({
  port: PORT,
  hostname: "127.0.0.1",
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/" || path === "/index.html") {
      return new Response(Bun.file(join(DEMO_DIR, "index.html")), {
        headers: { "Content-Type": "text/html; charset=utf-8", ...COOP_COEP_HEADERS },
      });
    }
    if (path === "/style.css") {
      return new Response(Bun.file(join(DEMO_DIR, "style.css")), {
        headers: { "Content-Type": "text/css; charset=utf-8", ...COOP_COEP_HEADERS },
      });
    }
    if (path === "/main.js") {
      return new Response(bundledJs, {
        headers: { "Content-Type": "application/javascript; charset=utf-8", ...COOP_COEP_HEADERS },
      });
    }
    if (path === "/unkernel.wasm" || path === "/dist/unkernel.wasm") {
      return new Response(Bun.file(resolveUnkernelAsset("unkernel.wasm")), {
        headers: { "Content-Type": "application/wasm", ...COOP_COEP_HEADERS },
      });
    }
    if (path === "/alpine.img") {
      const file = Bun.file(alpinePath);
      const size = file.size;
      const range = req.headers.get("range");
      if (range) {
        const m = /^bytes=(\d+)-(\d*)$/.exec(range);
        if (m) {
          const start = Number(m[1]);
          const end = m[2] ? Math.min(Number(m[2]), size - 1) : size - 1;
          if (start >= size || start > end) {
            return new Response(null, {
              status: 416,
              headers: {
                "Content-Range": `bytes */${size}`,
                ...COOP_COEP_HEADERS,
              },
            });
          }
          return new Response(file.slice(start, end + 1), {
            status: 206,
            headers: {
              "Content-Type": "application/octet-stream",
              "Accept-Ranges": "bytes",
              "Content-Range": `bytes ${start}-${end}/${size}`,
              "Content-Length": String(end - start + 1),
              ...COOP_COEP_HEADERS,
            },
          });
        }
      }
      return new Response(file, {
        headers: {
          "Content-Type": "application/octet-stream",
          "Accept-Ranges": "bytes",
          "Content-Length": String(size),
          ...COOP_COEP_HEADERS,
        },
      });
    }
    if (path === "/api/relay-info") {
      try {
        const res = await fetch(RELAY_INFO_URL);
        const json = await res.text();
        return new Response(json, {
          headers: { "Content-Type": "application/json", ...COOP_COEP_HEADERS },
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: `Relay info unavailable at ${RELAY_INFO_URL}: ${String(err)}` }),
          { status: 502, headers: { "Content-Type": "application/json", ...COOP_COEP_HEADERS } },
        );
      }
    }
    return new Response("Not Found", { status: 404, headers: COOP_COEP_HEADERS });
  },
});

console.log(`wisp-wt unkernel demo listening on http://127.0.0.1:${server.port}`);
