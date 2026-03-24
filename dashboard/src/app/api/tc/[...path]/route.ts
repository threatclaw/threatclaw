import { NextRequest, NextResponse } from "next/server";

/**
 * Proxy all /api/tc/* requests to the ThreatClaw Core API.
 * The Core runs on the same machine at port 3000.
 * This avoids CORS issues and keeps the API token server-side.
 */

const CORE_URL = process.env.TC_CORE_URL || "http://127.0.0.1:3000";
const CORE_TOKEN = process.env.TC_CORE_TOKEN || "";

async function proxyRequest(req: NextRequest, { params }: { params: { path: string[] } }) {
  const path = params.path.join("/");
  const url = new URL(req.url);
  const targetUrl = `${CORE_URL}/api/tc/${path}${url.search}`;

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
      signal: AbortSignal.timeout(300000), // 5 min for long operations (nmap, scans)
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

export async function GET(req: NextRequest, ctx: { params: { path: string[] } }) {
  return proxyRequest(req, ctx);
}

export async function POST(req: NextRequest, ctx: { params: { path: string[] } }) {
  return proxyRequest(req, ctx);
}

export async function PUT(req: NextRequest, ctx: { params: { path: string[] } }) {
  return proxyRequest(req, ctx);
}

export async function DELETE(req: NextRequest, ctx: { params: { path: string[] } }) {
  return proxyRequest(req, ctx);
}
