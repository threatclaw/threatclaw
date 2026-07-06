import { NextRequest, NextResponse } from "next/server";
import https from "node:https";
import { lookup as dnsLookup } from "node:dns";
import net from "node:net";

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

// FRONT-M4 — La liste noire par hostname (isSafeCloudBase) ne protège pas contre
// un hostname public qui *résout* vers une IP privée/metadata, ni contre le DNS
// rebinding (résolution différente entre le contrôle et la connexion). On valide
// donc l'IP RÉSOLUE et on épingle la connexion dessus.
function isPrivateOrReservedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    return (
      p[0] === 0 || // "this" network
      p[0] === 127 || // loopback
      p[0] === 10 || // RFC1918
      (p[0] === 192 && p[1] === 168) || // RFC1918
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || // RFC1918
      (p[0] === 169 && p[1] === 254) || // link-local + cloud metadata 169.254.169.254
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || // CGNAT RFC6598
      p[0] >= 224 // multicast + réservé
    );
  }
  if (net.isIPv6(ip)) {
    const s = ip.toLowerCase();
    if (s === "::1" || s === "::") return true; // loopback / unspecified
    if (s.startsWith("fe80") || s.startsWith("fc") || s.startsWith("fd")) return true; // link-local + ULA
    const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); // IPv4-mapped
    if (mapped) return isPrivateOrReservedIp(mapped[1]);
    return false;
  }
  return true; // format inconnu → traité comme non sûr
}

/**
 * FRONT-M4 — GET HTTPS épinglé sur l'IP résolue : la même résolution DNS sert
 * à la validation ET à la connexion (pas de fenêtre TOCTOU / rebinding), et le
 * hostname est conservé pour le SNI + la validation du certificat.
 */
function pinnedHttpsGet(
  testUrl: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = new URL(testUrl);
    } catch {
      reject(new Error("invalid URL"));
      return;
    }
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: `${u.pathname}${u.search}`,
        method: "GET",
        headers: { ...headers, Host: u.host },
        servername: u.hostname, // SNI + correspondance du certificat
        timeout: timeoutMs,
        // net.connect appelle lookup(host, opts, cb) et attend UNE adresse.
        lookup: (host, _opts, cb) => {
          dnsLookup(host, { all: true }, (err, addrs) => {
            if (err) {
              cb(err, "", 4);
              return;
            }
            const list = Array.isArray(addrs) ? addrs : [addrs];
            for (const a of list) {
              if (isPrivateOrReservedIp(a.address)) {
                cb(new Error("SSRF: résolution vers une adresse privée/réservée"), "", 4);
                return;
              }
            }
            const first = list[0];
            cb(null, first.address, first.family);
          });
        },
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (c) => {
          data += c;
          if (data.length > 1_000_000) req.destroy(new Error("response too large"));
        });
        res.on("end", () => resolve({ status: res.statusCode || 0, text: data }));
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
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

      // FRONT-M4 — connexion épinglée sur l'IP résolue validée (anti-SSRF /
      // anti-rebinding), plutôt qu'un fetch qui re-résout le DNS.
      const res = await pinnedHttpsGet(testUrl, headers, 10000);

      if (res.status >= 200 && res.status < 300) {
        let models: string[] = [];
        try {
          const data = JSON.parse(res.text);
          models = data?.data?.map((m: { id: string }) => m.id) || [];
        } catch {
          // corps non-JSON : connexion OK mais réponse inattendue.
        }
        return NextResponse.json({ ok: true, models: models.slice(0, 10) });
      } else {
        return NextResponse.json({
          ok: false,
          error: `HTTP ${res.status}: ${res.text.slice(0, 100)}`,
        });
      }
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : "Connection failed";
      return NextResponse.json({ ok: false, error: message });
    }
  }

  return NextResponse.json({ error: "Unknown action" }, { status: 400 });
}
