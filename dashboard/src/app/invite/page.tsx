"use client";
// Invitation acceptance: an invited user opens /invite?token=... and sets their
// own password. On success they are redirected to the login page. useSearchParams
// must live under a Suspense boundary (Next.js requirement).
import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";

function InviteForm() {
  const params = useSearchParams();
  const token = params.get("token") || "";
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const submit = async () => {
    setError(null);
    if (pw.length < 8) {
      setError("Le mot de passe doit faire au moins 8 caractères.");
      return;
    }
    if (pw !== confirm) {
      setError("Les mots de passe ne correspondent pas.");
      return;
    }
    setBusy(true);
    try {
      const r = await fetch("/api/auth/invitations/accept", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, newPassword: pw }),
      });
      const d = await r.json();
      if (r.ok && d.ok) {
        setDone(true);
        setTimeout(() => { window.location.href = "/login"; }, 1500);
      } else {
        setError(d.error || "Lien invalide ou expiré.");
      }
    } catch {
      setError("Erreur réseau.");
    }
    setBusy(false);
  };

  const inputStyle: React.CSSProperties = {
    width: "100%", padding: "10px 12px", borderRadius: 8, fontSize: 14,
    background: "var(--tc-input, #1a1a1a)", border: "1px solid var(--tc-border, #333)",
    color: "var(--tc-text, #eee)", outline: "none", fontFamily: "inherit", marginTop: 6,
  };

  return (
    <div style={{
      minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center",
      background: "var(--tc-bg, #0d0d0d)", fontFamily: "'JetBrains Mono', ui-monospace, monospace",
    }}>
      <div style={{
        width: 380, maxWidth: "90vw", padding: 28, borderRadius: 14,
        background: "var(--tc-surface, #161616)", border: "1px solid var(--tc-border, #2a2a2a)",
      }}>
        <div style={{ fontSize: 18, fontWeight: 700, color: "var(--tc-text, #eee)", marginBottom: 6 }}>
          ThreatClaw
        </div>
        <div style={{ fontSize: 13, color: "var(--tc-text-muted, #888)", marginBottom: 22 }}>
          Définissez votre mot de passe pour activer votre compte.
        </div>

        {done ? (
          <div style={{ color: "#30a050", fontSize: 14 }}>
            Mot de passe défini. Redirection vers la connexion…
          </div>
        ) : !token ? (
          <div style={{ color: "#d03020", fontSize: 14 }}>Lien invalide ou expiré.</div>
        ) : (
          <>
            <label style={{ fontSize: 12, color: "var(--tc-text-muted, #888)" }}>
              Nouveau mot de passe
              <input type="password" style={inputStyle} value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" />
            </label>
            <label style={{ fontSize: 12, color: "var(--tc-text-muted, #888)", display: "block", marginTop: 14 }}>
              Confirmer
              <input type="password" style={inputStyle} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password"
                onKeyDown={(e) => e.key === "Enter" && submit()} />
            </label>
            {error && <div style={{ color: "#d03020", fontSize: 12, marginTop: 12 }}>{error}</div>}
            <button
              onClick={submit}
              disabled={busy}
              style={{
                width: "100%", marginTop: 20, padding: "11px 0", fontSize: 13, fontWeight: 700,
                letterSpacing: "0.1em", textTransform: "uppercase", background: "var(--tc-red, #d03020)",
                color: "#fff", border: "none", borderRadius: 8, cursor: busy ? "default" : "pointer",
                fontFamily: "inherit", opacity: busy ? 0.7 : 1,
              }}
            >
              {busy ? "…" : "Activer mon compte"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export default function InvitePage() {
  return (
    <Suspense fallback={null}>
      <InviteForm />
    </Suspense>
  );
}
