import { NextRequest, NextResponse } from "next/server";

const CORE_URL = process.env.TC_CORE_URL || "http://127.0.0.1:3000";
const CORE_TOKEN = process.env.TC_CORE_TOKEN || process.env.GATEWAY_AUTH_TOKEN || "";

async function proxyRequest(req: NextRequest) {
  // Extract the path after /api/tc/
  const url = new URL(req.url);
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
    const data = await resp.text();

    return new NextResponse(data, {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
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
