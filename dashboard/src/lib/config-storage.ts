// Helpers for the localStorage fallback used when the backend config save is
// unreachable. We must NEVER persist secrets (API keys, tokens, passwords) in
// clear text in the browser — an XSS would otherwise exfiltrate every connector
// credential at once (CodeQL "clear text storage of sensitive information").
//
// stripSecrets() deep-drops any field whose key looks like a secret, so the
// non-sensitive config is still preserved across a reload while credentials are
// not written to localStorage. The user re-enters secrets if the backend was
// down — an acceptable trade for not storing them in the clear.

const SECRET_KEY = /(api[-_ ]?key|password|passwd|secret|token)/i;

export function stripSecrets<T>(value: T): T {
  const walk = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(walk);
    if (v !== null && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        if (SECRET_KEY.test(k)) continue; // drop secret-bearing fields
        out[k] = walk(val);
      }
      return out;
    }
    return v;
  };
  return walk(value) as T;
}
