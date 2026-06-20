"use client";
// Config -> My account: shows the current user's identity (read-only) and lets
// them change their password and sign out of every session.
import { useState, useEffect, useCallback } from "react";
import { Lock, CheckCircle, XCircle, LogOut, Loader2 } from "lucide-react";
import { useLocale } from "@/lib/useLocale";

const cardStyle: React.CSSProperties = {
  background: "var(--tc-surface)", border: "1px solid var(--tc-border)",
  borderRadius: 12, padding: "16px 20px", marginBottom: 16,
};
const labelStyle: React.CSSProperties = {
  fontSize: 11, fontWeight: 700, textTransform: "uppercase" as const,
  letterSpacing: "0.05em", color: "var(--tc-text-muted)", marginBottom: 8,
};
const inputStyle: React.CSSProperties = {
  width: "100%", padding: "8px 12px", borderRadius: 8, fontSize: 13,
  background: "var(--tc-input)", border: "1px solid var(--tc-border)",
  color: "var(--tc-text)", outline: "none", fontFamily: "inherit",
};
const btnStyle: React.CSSProperties = {
  padding: "9px 18px", fontSize: 12, fontWeight: 700, letterSpacing: "0.1em",
  textTransform: "uppercase" as const, background: "var(--tc-red)", color: "#fff",
  border: "none", borderRadius: 8, cursor: "pointer", fontFamily: "inherit",
  display: "inline-flex", alignItems: "center", gap: 8,
};

interface Me {
  email: string;
  display_name: string;
  role: string;
}

const roleLabel = (role: string, fr: boolean): string => {
  if (role === "admin") return fr ? "Administrateur" : "Administrator";
  if (role === "analyst") return fr ? "Analyste" : "Analyst";
  if (role === "viewer") return fr ? "Lecteur" : "Viewer";
  return role;
};

export default function AccountTab() {
  const locale = useLocale();
  const fr = locale === "fr";
  const [me, setMe] = useState<Me | null>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const loadMe = useCallback(async () => {
    try {
      const r = await fetch("/api/auth/me");
      const d = await r.json();
      if (d.user) setMe(d.user);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    loadMe();
  }, [loadMe]);

  const changePassword = async () => {
    setMsg(null);
    if (next.length < 8) {
      setMsg({ ok: false, text: fr ? "Le nouveau mot de passe doit faire au moins 8 caractères" : "New password must be at least 8 characters" });
      return;
    }
    if (next !== confirm) {
      setMsg({ ok: false, text: fr ? "Les mots de passe ne correspondent pas" : "Passwords do not match" });
      return;
    }
    setSaving(true);
    try {
      const r = await fetch("/api/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: current, newPassword: next }),
      });
      const d = await r.json();
      if (r.ok && d.ok) {
        setMsg({ ok: true, text: fr ? "Mot de passe modifié" : "Password changed" });
        setCurrent(""); setNext(""); setConfirm("");
      } else {
        setMsg({ ok: false, text: d.error || (fr ? "Échec" : "Failed") });
      }
    } catch {
      setMsg({ ok: false, text: fr ? "Erreur réseau" : "Network error" });
    }
    setSaving(false);
  };

  const signOutEverywhere = async () => {
    try {
      await fetch("/api/auth/logout-all", { method: "POST" });
    } catch {
      /* ignore */
    }
    window.location.href = "/login";
  };

  return (
    <div>
      <div style={cardStyle}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 18 }}>
          <Lock size={18} color="var(--tc-red)" />
          <span style={{ fontSize: 16, fontWeight: 700 }}>{fr ? "Mon compte" : "My account"}</span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div>
            <div style={labelStyle}>{fr ? "Email" : "Email"}</div>
            <div style={{ fontSize: 13, color: "var(--tc-text)" }}>{me?.email ?? "—"}</div>
          </div>
          <div>
            <div style={labelStyle}>{fr ? "Nom affiché" : "Display name"}</div>
            <div style={{ fontSize: 13, color: "var(--tc-text)" }}>{me?.display_name ?? "—"}</div>
          </div>
          <div>
            <div style={labelStyle}>{fr ? "Rôle" : "Role"}</div>
            <div style={{ fontSize: 13, color: "var(--tc-text)" }}>{me ? roleLabel(me.role, fr) : "—"}</div>
          </div>
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>
          {fr ? "Changer le mot de passe" : "Change password"}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 12, maxWidth: 420 }}>
          <div>
            <div style={labelStyle}>{fr ? "Mot de passe actuel" : "Current password"}</div>
            <input type="password" style={inputStyle} value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />
          </div>
          <div>
            <div style={labelStyle}>{fr ? "Nouveau mot de passe" : "New password"}</div>
            <input type="password" style={inputStyle} value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />
          </div>
          <div>
            <div style={labelStyle}>{fr ? "Confirmer" : "Confirm"}</div>
            <input type="password" style={inputStyle} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
          </div>
          {msg && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: msg.ok ? "#30a050" : "#d03020" }}>
              {msg.ok ? <CheckCircle size={14} /> : <XCircle size={14} />} {msg.text}
            </div>
          )}
          <div>
            <button style={btnStyle} onClick={changePassword} disabled={saving}>
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Lock size={14} />}
              {fr ? "Modifier" : "Update"}
            </button>
          </div>
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>
          {fr ? "Sécurité de la session" : "Session security"}
        </div>
        <div style={{ fontSize: 12, color: "var(--tc-text-muted)", marginBottom: 14 }}>
          {fr
            ? "Déconnecte toutes vos sessions actives, sur cet appareil et les autres."
            : "Signs out all your active sessions, on this device and others."}
        </div>
        <button
          style={{ ...btnStyle, background: "var(--tc-input)", color: "var(--tc-text)", border: "1px solid var(--tc-border)" }}
          onClick={signOutEverywhere}
        >
          <LogOut size={14} /> {fr ? "Se déconnecter partout" : "Sign out everywhere"}
        </button>
      </div>
    </div>
  );
}
