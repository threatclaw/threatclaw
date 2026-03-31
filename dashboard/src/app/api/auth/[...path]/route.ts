import { NextRequest, NextResponse } from "next/server";

const CORE_URL = process.env.TC_CORE_URL || "http://127.0.0.1:3000";

async function proxyAuth(req: NextRequest) {
  const url = new URL(req.url);
  const authPath = url.pathname.replace(/^\/api\/auth\//, "");
  const targetUrl = `${CORE_URL}/api/auth/${authPath}${url.search}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Forward cookies (session cookie for /me and /logout)
  const cookie = req.headers.get("cookie");
  if (cookie) {
    headers["Cookie"] = cookie;
  }

  // Forward client IP for brute force tracking
  const forwarded = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown";
  headers["X-Forwarded-For"] = forwarded;
  const ua = req.headers.get("user-agent") || "unknown";
  headers["User-Agent"] = ua;

  try {
    const fetchOptions: RequestInit = {
      method: req.method,
      headers,
      signal: AbortSignal.timeout(10000),
    };

    if (req.method !== "GET" && req.method !== "HEAD") {
      const body = await req.text();
      if (body) fetchOptions.body = body;
    }

    const resp = await fetch(targetUrl, fetchOptions);
    const data = await resp.text();

    const respHeaders: Record<string, string> = {
      "Content-Type": resp.headers.get("Content-Type") || "application/json",
    };

    // Forward Set-Cookie from backend (session cookie)
    const setCookie = resp.headers.get("Set-Cookie");
    if (setCookie) {
      respHeaders["Set-Cookie"] = setCookie;
    }

    return new NextResponse(data, {
      status: resp.status,
      headers: respHeaders,
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Auth proxy error";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}

export async function GET(req: NextRequest) { return proxyAuth(req); }
export async function POST(req: NextRequest) { return proxyAuth(req); }
