import { NextRequest, NextResponse } from "next/server";

const CORE_URL = process.env.TC_CORE_URL || "http://127.0.0.1:3000";
const CORE_TOKEN = process.env.TC_CORE_TOKEN || process.env.GATEWAY_AUTH_TOKEN || "";

// This proxy attaches the privileged core Bearer token to every forwarded
// request. The page middleware (proxy.ts) deliberately excludes /api/*, so the
// session MUST be validated here — otherwise any unauthenticated caller reaching
// this route drives the core API (block IP, isolate host, disable user…) with
// full privileges. Validate the tc_session cookie against the core before
// attaching the token.
async function hasValidSession(req: NextRequest): Promise<boolean> {
  const cookie = req.headers.get("cookie");
  if (!cookie || !cookie.includes("tc_session")) return false;
  try {
    const resp = await fetch(`${CORE_URL}/api/auth/me`, {
      headers: { Cookie: cookie },
      signal: AbortSignal.timeout(5000),
    });
    return resp.ok;
  } catch {
    return false;
  }
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
    pathname === "/api/tc/agent/install.ps1"
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
  // Endpoint-agent ingress: forward the agent's own webhook token + the
  // hostname / user-agent so the core handler can match it against the
  // per-source token stored in settings. The handler also accepts the
  // token as a query parameter, but agents that prefer header auth must
  // still work end-to-end.
  if (isAgent) {
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
      const body = await req.text();
      if (body) fetchOptions.body = body;
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
