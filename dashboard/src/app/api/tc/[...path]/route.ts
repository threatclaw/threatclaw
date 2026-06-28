import { NextRequest, NextResponse } from "next/server";
import { createHash } from "crypto";

const CORE_URL = process.env.TC_CORE_URL || "http://127.0.0.1:3000";
const CORE_TOKEN = process.env.TC_CORE_TOKEN || process.env.GATEWAY_AUTH_TOKEN || "";

// Session-validation cache + spike-tolerant timeout.
//
// Every /api/tc/* call used to fire its own /api/auth/me probe with a 5 s
// hard timeout and no memoisation. A page mounting 6-8 fetches in parallel
// therefore drove 6-8 concurrent /api/auth/me on the core, each one
// writing the renewed sliding-window expiry back to the settings table.
// When the IE cycle (or any other heavy write loop) bumped DB latency
// above 5 s for a few seconds, the timeout fired, the proxy returned 401,
// and the browser showed Next's generic "This page couldn't load" or
// emptied tables until the user signed out and back in. Symptom matched
// "1-2 times a day" from a customer report on cyb06.
//
// Mitigation:
//   1. Memoise per-cookie validation in-process for 45 s on success,
//      5 s on failure. Same-cookie concurrent fetches collapse onto a
//      single probe.
//   2. Raise the probe timeout to 15 s and retry once on timeout
//      (not on a real 401 — those propagate immediately so a logged-out
//      user isn't kept around for 30 extra seconds).
const SESSION_VALIDATION_TTL_OK_MS = 45_000;
const SESSION_VALIDATION_TTL_KO_MS = 5_000;
const SESSION_VALIDATION_TIMEOUT_MS = 15_000;

type ValidationCacheEntry = { ok: boolean; expiresAt: number };
const sessionValidationCache = new Map<string, ValidationCacheEntry>();

// Hash the token rather than indexing by the raw value — keeps the
// secret out of any accidental Map dump and gives a stable bounded key.
function sessionCacheKey(cookie: string): string | null {
  const m = cookie.match(/(?:^|;\s*)tc_session=([^;]+)/);
  if (!m) return null;
  return createHash("sha256").update(m[1]).digest("hex");
}

type ProbeResult = "ok" | "unauthorized" | "timeout" | "error";

async function probeAuthMe(cookie: string, timeoutMs: number): Promise<ProbeResult> {
  try {
    const resp = await fetch(`${CORE_URL}/api/auth/me`, {
      headers: { Cookie: cookie },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (resp.ok) return "ok";
    if (resp.status === 401) return "unauthorized";
    return "error";
  } catch (e) {
    if (e instanceof DOMException && e.name === "TimeoutError") return "timeout";
    return "error";
  }
}

// This proxy attaches the privileged core Bearer token to every forwarded
// request. The page middleware (proxy.ts) deliberately excludes /api/*, so the
// session MUST be validated here — otherwise any unauthenticated caller reaching
// this route drives the core API (block IP, isolate host, disable user…) with
// full privileges. Validate the tc_session cookie against the core before
// attaching the token.
async function hasValidSession(req: NextRequest): Promise<boolean> {
  const cookie = req.headers.get("cookie");
  if (!cookie || !cookie.includes("tc_session")) return false;

  const key = sessionCacheKey(cookie);
  const now = Date.now();
  if (key) {
    const cached = sessionValidationCache.get(key);
    if (cached && cached.expiresAt > now) {
      return cached.ok;
    }
  }

  let result = await probeAuthMe(cookie, SESSION_VALIDATION_TIMEOUT_MS);
  if (result === "timeout") {
    // Single retry — the IE cycle write spike usually clears within a
    // second once the cache window opens. Don't retry on a real 401:
    // forwarding a stale session would cost the user 15 extra seconds
    // before the UI even sees the rejection.
    result = await probeAuthMe(cookie, SESSION_VALIDATION_TIMEOUT_MS);
  }

  const ok = result === "ok";
  if (key) {
    sessionValidationCache.set(key, {
      ok,
      expiresAt: now + (ok ? SESSION_VALIDATION_TTL_OK_MS : SESSION_VALIDATION_TTL_KO_MS),
    });
    // Bounded clean-up: a single-tenant SOC dashboard barely accumulates
    // entries, but a long-running process with rotating tokens shouldn't
    // grow this map without an upper bound either.
    if (sessionValidationCache.size > 1024) {
      sessionValidationCache.forEach((v, k) => {
        if (v.expiresAt <= now) sessionValidationCache.delete(k);
      });
    }
  }
  return ok;
}

// Endpoint-agent ingress paths carry their own webhook_token in the
// request, validated by the core handler (constant-time compare against
// the per-source token stored in `settings`). External agents installed
// on customer Windows / Linux endpoints reach the gateway over the
// public IP — they have no dashboard session and never will. Skip the
// session check for these paths so the proxy can forward them to core.
// The Bearer is still attached (core's middleware still passes), then
// the core handler runs the webhook_token check and silent-drops on
// mismatch. Keep this list narrow: any route added here MUST validate
// its own per-source token.
function isAgentIngressPath(pathname: string): boolean {
  return (
    pathname.startsWith("/api/tc/webhook/ingest/") ||
    pathname === "/api/tc/agent/manifest" ||
    pathname === "/api/tc/agent/install.sh" ||
    pathname === "/api/tc/agent/install.ps1" ||
    pathname === "/api/tc/agent/uninstall.sh" ||
    pathname === "/api/tc/agent/uninstall.ps1"
  );
}

async function proxyRequest(req: NextRequest) {
  const url = new URL(req.url);
  const isAgent = isAgentIngressPath(url.pathname);
  if (!isAgent && !(await hasValidSession(req))) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Extract the path after /api/tc/
  const fullPath = url.pathname;
  const tcPath = fullPath.replace(/^\/api\/tc\//, "");
  // Forward request — token is sent only via Authorization header
  const targetUrl = `${CORE_URL}/api/tc/${tcPath}${url.search}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (CORE_TOKEN) {
    headers["Authorization"] = `Bearer ${CORE_TOKEN}`;
  }
  // Forward the browser session cookie to the core for non-agent
  // routes. Handlers added in v1.0.38 (operator decisions: Resolve /
  // FP / Accept Risk / Snooze / Delete) identify the actor by
  // resolving the tc_session cookie against the dashboard auth table.
  // Without the cookie, the core handler returned 401 "not
  // authenticated" on every click. The Bearer authenticates the proxy
  // itself to the gateway; the cookie identifies the user. Skip this
  // on agent ingress routes — they authenticate by webhook_token, not
  // by a dashboard session.
  if (!isAgent) {
    const cookie = req.headers.get("cookie");
    if (cookie) headers["Cookie"] = cookie;
  } else {
    const webhookToken = req.headers.get("x-webhook-token");
    if (webhookToken) headers["X-Webhook-Token"] = webhookToken;
    const ua = req.headers.get("user-agent");
    if (ua) headers["User-Agent"] = ua;
  }

  try {
    const fetchOptions: RequestInit = {
      method: req.method,
      headers,
      signal: AbortSignal.timeout(300000), // 5 min for long operations
    };

    if (req.method !== "GET" && req.method !== "HEAD") {
      // Read the body as RAW BYTES, not text. An endpoint agent may send a
      // gzip-compressed body (Content-Encoding: gzip, negotiated via the
      // manifest accepts_gzip flag); decoding it as text here would mangle the
      // binary gzip stream into invalid UTF-8 and the core would then fail to
      // parse it ("invalid JSON"). Forwarding bytes is equally correct for the
      // plain-JSON dashboard calls. When the agent compressed the body, forward
      // its Content-Encoding so the core knows to decompress before parsing.
      const bodyBuf = await req.arrayBuffer();
      if (bodyBuf.byteLength > 0) {
        fetchOptions.body = bodyBuf;
        const enc = req.headers.get("content-encoding");
        if (enc) headers["Content-Encoding"] = enc;
      }
    }

    const resp = await fetch(targetUrl, fetchOptions);
    const contentType = resp.headers.get("Content-Type") || "application/json";

    // Binary responses (PDF, etc.) — pass through as-is
    if (!contentType.includes("json") && !contentType.includes("text")) {
      const buffer = await resp.arrayBuffer();
      const respHeaders: Record<string, string> = { "Content-Type": contentType };
      const disposition = resp.headers.get("Content-Disposition");
      if (disposition) respHeaders["Content-Disposition"] = disposition;
      return new NextResponse(buffer, {
        status: resp.status,
        headers: respHeaders,
      });
    }

    // JSON/text responses
    const data = await resp.text();
    return new NextResponse(data, {
      status: resp.status,
      headers: { "Content-Type": contentType },
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Proxy error";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}

export async function GET(req: NextRequest) {
  return proxyRequest(req);
}

export async function POST(req: NextRequest) {
  return proxyRequest(req);
}

export async function PUT(req: NextRequest) {
  return proxyRequest(req);
}

export async function DELETE(req: NextRequest) {
  return proxyRequest(req);
}
