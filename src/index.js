/**
 * bumblcat-photon — Cloudflare Worker HTTP proxy
 * Implements server-side TLS so the browser never touches libcurl WASM for HTTPS.
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Expose-Headers": "*",
};

const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
  // Cloudflare auto-decompresses bodies; forwarding these would lie about encoding
  "content-encoding", "content-length",
]);

function isPrivate(hostname) {
  if (["localhost", "127.0.0.1", "::1", "0.0.0.0"].includes(hostname)) return true;
  const p = hostname.split(".").map(Number);
  if (p.length !== 4 || p.some(isNaN)) return false;
  return (
    p[0] === 10 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254)
  );
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname === "/") {
      return new Response("bumblcat-photon v1 — online", {
        headers: { "Content-Type": "text/plain", "X-Powered-By": "photon", ...CORS },
      });
    }

    if (url.pathname !== "/proxy") {
      return new Response("not found", { status: 404, headers: CORS });
    }

    // ── Decode target ──────────────────────────────────────────────────────
    const rawTarget = request.headers.get("X-Photon-URL");
    if (!rawTarget) return new Response("missing X-Photon-URL", { status: 400, headers: CORS });

    let target;
    try { target = atob(rawTarget); } catch {
      return new Response("bad X-Photon-URL encoding", { status: 400, headers: CORS });
    }

    let targetURL;
    try { targetURL = new URL(target); } catch {
      return new Response("bad target URL", { status: 400, headers: CORS });
    }

    if (isPrivate(targetURL.hostname)) {
      return new Response("blocked: private address", { status: 403, headers: CORS });
    }

    const method = request.headers.get("X-Photon-Method") || request.method;

    // ── Build upstream headers ─────────────────────────────────────────────
    let reqHeadersRaw = {};
    try { reqHeadersRaw = JSON.parse(request.headers.get("X-Photon-Headers") || "{}"); } catch {}

    const upstreamHeaders = new Headers();
    for (const [k, v] of Object.entries(reqHeadersRaw)) {
      const lk = k.toLowerCase();
      if (!HOP_BY_HOP.has(lk) && lk !== "host") upstreamHeaders.set(k, v);
    }

    // ── Upstream fetch ─────────────────────────────────────────────────────
    let upstream;
    try {
      upstream = await fetch(target, {
        method,
        headers: upstreamHeaders,
        body: ["GET", "HEAD"].includes(method.toUpperCase()) ? undefined : request.body,
        redirect: "manual",
      });
    } catch (e) {
      return new Response(`photon upstream error: ${e.message}`, { status: 502, headers: CORS });
    }

    // ── Build response ─────────────────────────────────────────────────────
    const respHeaders = new Headers(CORS);
    const forwardedHeaders = [];

    for (const [k, v] of upstream.headers) {
      const lk = k.toLowerCase();
      if (HOP_BY_HOP.has(lk)) continue;
      if (lk.startsWith("access-control-")) continue; // never let upstream override our CORS headers
      respHeaders.set(k, v);
      forwardedHeaders.push([k, v]);
    }

    respHeaders.set("X-Photon-Status", String(upstream.status));
    respHeaders.set("X-Photon-Status-Text", upstream.statusText);
    respHeaders.set("X-Photon-Resp-Headers", JSON.stringify(forwardedHeaders));

    return new Response(upstream.body, { status: 200, headers: respHeaders });
  },
};
