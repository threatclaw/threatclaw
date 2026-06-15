import { NextRequest, NextResponse } from "next/server";

const SERVER_URL = process.env.OLLAMA_URL || "http://127.0.0.1:11434";
const CORE_URL = process.env.TC_CORE_URL || "http://127.0.0.1:3000";

// Unauthenticated callers must not be able to pull models (disk exhaustion) or
// reach the test_cloud SSRF below — gate the whole route on a valid session.
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

// SSRF guard for the cloud-key test: only an explicit https URL to a public
// host. Blocks cloud metadata (169.254.169.254), localhost and RFC-1918 ranges
// that an attacker could otherwise reach via baseUrl.
function isSafeCloudBase(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  const h = u.hostname.toLowerCase();
  return !(
    h === "localhost" ||
    h.endsWith(".internal") ||
    h.endsWith(".local") ||
    /^127\./.test(h) ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^169\.254\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h)
  );
}

/** GET /api/ollama?url=... — list models */
export async function GET(req: NextRequest) {
  if (!(await hasValidSession(req))) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  // Always use server-side OLLAMA_URL (client can't reach Docker network)
  const url = SERVER_URL;

  try {
    const res = await fetch(`${url}/api/tags`, {
      signal: AbortSignal.timeout(5000),
    });
    const data = await res.json();
    return NextResponse.json(data);
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Connection failed";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}

/** POST /api/ollama — pull model or test model */
export async function POST(req: NextRequest) {
  if (!(await hasValidSession(req))) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const body = await req.json();
  // Always use server-side OLLAMA_URL
  const url = SERVER_URL;
  const action = body.action || "pull";

  // Pull a model
  if (action === "pull") {
    const model = body.model;
    if (!model) return NextResponse.json({ error: "Missing model name" }, { status: 400 });

    try {
      const res = await fetch(`${url}/api/pull`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: model, stream: false }),
        signal: AbortSignal.timeout(600000), // 10 min for large models
      });
      const data = await res.json();
      return NextResponse.json({ ok: true, status: data.status || "success" });
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : "Pull failed";
      return NextResponse.json({ ok: false, error: message }, { status: 502 });
    }
  }

  // Test a model with a simple prompt
  if (action === "test") {
    const model = body.model;
    if (!model) return NextResponse.json({ error: "Missing model name" }, { status: 400 });

    try {
      const res = await fetch(`${url}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model,
          messages: [{ role: "user", content: "Réponds uniquement: OK" }],
          stream: false,
          options: { num_predict: 10 },
        }),
        signal: AbortSignal.timeout(30000),
      });
      const data = await res.json();
      const content = data?.message?.content || data?.response || "";
      return NextResponse.json({ ok: true, response: content.slice(0, 100) });
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : "Test failed";
      return NextResponse.json({ ok: false, error: message }, { status: 502 });
    }
  }

  // Test cloud API key
  if (action === "test_cloud") {
    const backend = body.backend;
    const apiKey = body.apiKey;
    if (!apiKey) return NextResponse.json({ ok: false, error: "Missing API key" });

    try {
      let testUrl = "";
      const headers: Record<string, string> = {};

      if (backend === "mistral") {
        testUrl = "https://api.mistral.ai/v1/models";
        headers["Authorization"] = `Bearer ${apiKey}`;
      } else if (backend === "anthropic") {
        testUrl = "https://api.anthropic.com/v1/models";
        headers["x-api-key"] = apiKey;
        headers["anthropic-version"] = "2023-06-01";
      } else {
        // OpenAI compatible
        const baseUrl = body.baseUrl || "https://api.openai.com";
        if (!isSafeCloudBase(baseUrl)) {
          return NextResponse.json(
            { ok: false, error: "Invalid base URL (must be https to a public host)" },
            { status: 400 },
          );
        }
        testUrl = `${baseUrl}/v1/models`;
        headers["Authorization"] = `Bearer ${apiKey}`;
      }

      const res = await fetch(testUrl, {
        headers,
        signal: AbortSignal.timeout(10000),
      });

      if (res.ok) {
        const data = await res.json();
        const models = data?.data?.map((m: { id: string }) => m.id) || [];
        return NextResponse.json({ ok: true, models: models.slice(0, 10) });
      } else {
        const text = await res.text().catch(() => "");
        return NextResponse.json({ ok: false, error: `HTTP ${res.status}: ${text.slice(0, 100)}` });
      }
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : "Connection failed";
      return NextResponse.json({ ok: false, error: message });
    }
  }

  return NextResponse.json({ error: "Unknown action" }, { status: 400 });
}
