import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Routes that don't require authentication. `/invite` must be reachable by an
// invited user who has no session yet, so they can set their password.
const PUBLIC_PATHS = ["/login", "/invite", "/api/", "/_next/", "/favicon.ico"];

// FRONT-M2 — Content-Security-Policy à nonce par requête.
//
// Auparavant la CSP (posée par nginx) autorisait 'unsafe-inline' et
// 'unsafe-eval' sur script-src, ce qui neutralise la protection anti-XSS. On
// pose désormais la CSP ici, avec un nonce unique par réponse : seuls les
// scripts portant ce nonce (Next l'ajoute à ses propres <script> via l'en-tête
// x-nonce) et les scripts same-origin ('self') sont exécutés. 'unsafe-inline' et
// 'unsafe-eval' disparaissent de script-src.
//
// style-src conserve 'unsafe-inline' : Next / styled-jsx émettent des styles
// inline non-nonçables sans casse ; le durcissement porte sur les scripts, qui
// sont le vecteur XSS.
function buildCsp(nonce: string): string {
  return (
    [
      "default-src 'self'",
      `script-src 'self' 'nonce-${nonce}'`,
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self' wss: ws:",
      "frame-ancestors 'self'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; ") + ";"
  );
}

function withSecurity(request: NextRequest, redirectTo?: URL): NextResponse {
  // Web Crypto est disponible dans le runtime middleware (Edge).
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const csp = buildCsp(nonce);

  // Next lit la CSP dans l'en-tête de REQUÊTE pour propager le nonce à ses
  // scripts de bootstrap/hydratation.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("content-security-policy", csp);

  const response = redirectTo
    ? NextResponse.redirect(redirectTo)
    : NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("content-security-policy", csp);
  return response;
}

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public paths (still get the CSP).
  if (PUBLIC_PATHS.some(p => pathname.startsWith(p))) {
    return withSecurity(request);
  }

  // Check for session cookie
  const sessionCookie = request.cookies.get("tc_session");
  if (!sessionCookie?.value) {
    // No session — redirect to login
    return withSecurity(request, new URL("/login", request.url));
  }

  return withSecurity(request);
}

export const config = {
  // Apply to all routes except static files and API
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api/).*)"],
};
