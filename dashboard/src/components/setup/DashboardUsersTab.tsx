"use client";
// Config -> Dashboard users (admin only). Lists dashboard accounts and lets an
// admin invite, change role, enable/disable, reset, and delete them. Sensitive
// actions require step-up (re-entry of the admin's own password). The backend
// enforces every check; this UI self-gates for a clean experience.
import { useState, useEffect, useCallback } from "react";
import { Users, UserPlus, Trash2, Loader2, ShieldAlert, Copy, CheckCircle, RotateCcw, KeyRound } from "lucide-react";
import { useLocale } from "@/lib/useLocale";

const cardStyle: React.CSSProperties = {
  background: "var(--tc-surface)", border: "1px solid var(--tc-border)",
  borderRadius: 12, padding: "16px 20px", marginBottom: 16,
};
const labelStyle: React.CSSProperties = {
  fontSize: 11, fontWeight: 700, textTransform: "uppercase" as const,
  letterSpacing: "0.05em", color: "var(--tc-text-muted)", marginBottom: 6,
};
const inputStyle: React.CSSProperties = {
  width: "100%", padding: "8px 12px", borderRadius: 8, fontSize: 13,
  background: "var(--tc-input)", border: "1px solid var(--tc-border)",
  color: "var(--tc-text)", outline: "none", fontFamily: "inherit",
};
const btn: React.CSSProperties = {
  padding: "8px 14px", fontSize: 12, fontWeight: 700, border: "none",
  borderRadius: 8, cursor: "pointer", fontFamily: "inherit",
  display: "inline-flex", alignItems: "center", gap: 6,
};
const btnPrimary: React.CSSProperties = { ...btn, background: "var(--tc-red)", color: "#fff" };
const btnGhost: React.CSSProperties = { ...btn, background: "var(--tc-input)", color: "var(--tc-text)", border: "1px solid var(--tc-border)" };

interface DashUser {
  id: string;
  email: string;
  display_name: string;
  role: string;
  status: string;
  can_remediate: boolean;
  must_change_password: boolean;
}

const ROLES = ["admin", "analyst", "viewer"];

export default function DashboardUsersTab() {
  const locale = useLocale();
  const fr = locale === "fr";
  const [canManage, setCanManage] = useState<boolean | null>(null);
  const [users, setUsers] = useState<DashUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // invite modal
  const [showInvite, setShowInvite] = useState(false);
  const [invEmail, setInvEmail] = useState("");
  const [invName, setInvName] = useState("");
  const [invRole, setInvRole] = useState("analyst");
  const [invRemediate, setInvRemediate] = useState(true);
  const [invPw, setInvPw] = useState("");
  const [invBusy, setInvBusy] = useState(false);
  const [invLink, setInvLink] = useState<string | null>(null);
  const [invErr, setInvErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const meR = await fetch("/api/auth/me");
      const me = await meR.json();
      const perms: string[] = me?.permissions ?? [];
      const allowed = perms.includes("users:manage");
      setCanManage(allowed);
      if (!allowed) {
        setLoading(false);
        return;
      }
      const r = await fetch("/api/auth/users");
      const d = await r.json();
      if (r.ok && d.ok) setUsers(d.users || []);
      else setError(d.error || "Error");
    } catch {
      setError(fr ? "Erreur réseau" : "Network error");
    }
    setLoading(false);
  }, [fr]);

  useEffect(() => { load(); }, [load]);

  const submitInvite = async () => {
    setInvErr(null);
    setInvLink(null);
    setInvBusy(true);
    try {
      const r = await fetch("/api/auth/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: invEmail.trim(),
          displayName: invName.trim() || invEmail.trim(),
          role: invRole,
          canRemediate: invRemediate,
          currentPassword: invPw,
        }),
      });
      const d = await r.json();
      if (r.ok && d.ok) {
        if (d.invite_link) {
          setInvLink(d.invite_link);
        } else {
          closeInvite();
        }
        await load();
      } else {
        setInvErr(d.error || (fr ? "Échec" : "Failed"));
      }
    } catch {
      setInvErr(fr ? "Erreur réseau" : "Network error");
    }
    setInvBusy(false);
  };

  const closeInvite = () => {
    setShowInvite(false);
    setInvEmail(""); setInvName(""); setInvRole("analyst");
    setInvRemediate(true); setInvPw(""); setInvLink(null); setInvErr(null);
    setCopied(false);
  };

  // Step-up actions: prompt for the admin password inline.
  const adminPrompt = (): string | null => {
    const pw = window.prompt(fr ? "Confirmez avec votre mot de passe administrateur" : "Confirm with your admin password");
    return pw && pw.length > 0 ? pw : null;
  };

  const patchUser = async (u: DashUser, body: Record<string, unknown>) => {
    const pw = adminPrompt();
    if (!pw) return;
    const r = await fetch(`/api/auth/users/${u.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...body, currentPassword: pw }),
    });
    const d = await r.json();
    if (!r.ok || !d.ok) alert(d.error || (fr ? "Échec" : "Failed"));
    await load();
  };

  const deleteUser = async (u: DashUser) => {
    if (!window.confirm(fr ? `Supprimer définitivement ${u.email} ?` : `Permanently delete ${u.email}?`)) return;
    const pw = adminPrompt();
    if (!pw) return;
    const r = await fetch(`/api/auth/users/${u.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ currentPassword: pw }),
    });
    const d = await r.json();
    if (!r.ok || !d.ok) alert(d.error || (fr ? "Échec" : "Failed"));
    await load();
  };

  const regen = async (u: DashUser, kind: "reinvite" | "reset-password") => {
    const r = await fetch(`/api/auth/users/${u.id}/${kind}`, { method: "POST" });
    const d = await r.json();
    if (r.ok && d.ok) {
      if (d.invite_link) {
        window.prompt(fr ? "Lien à transmettre (copiez-le) :" : "Link to share (copy it):", `${window.location.origin}${d.invite_link}`);
      } else {
        alert(fr ? "Email envoyé." : "Email sent.");
      }
    } else {
      alert(d.error || (fr ? "Échec" : "Failed"));
    }
  };

  if (loading) {
    return <div style={{ padding: 40, textAlign: "center", color: "var(--tc-text-muted)", fontSize: 13 }}>{fr ? "Chargement…" : "Loading…"}</div>;
  }

  if (canManage === false) {
    return (
      <div style={cardStyle}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <ShieldAlert size={18} color="var(--tc-red)" />
          <span style={{ fontSize: 14, fontWeight: 700 }}>{fr ? "Réservé aux administrateurs" : "Administrators only"}</span>
        </div>
        <div style={{ fontSize: 12, color: "var(--tc-text-muted)", marginTop: 8 }}>
          {fr ? "La gestion des comptes du dashboard est réservée aux administrateurs." : "Dashboard account management is restricted to administrators."}
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Users size={18} color="var(--tc-red)" />
          <span style={{ fontSize: 16, fontWeight: 700 }}>{fr ? "Utilisateurs du dashboard" : "Dashboard users"}</span>
        </div>
        <button style={btnPrimary} onClick={() => setShowInvite(true)}>
          <UserPlus size={14} /> {fr ? "Inviter" : "Invite"}
        </button>
      </div>

      {error && <div style={{ ...cardStyle, color: "#d03020" }}>{error}</div>}

      <div style={{ ...cardStyle, padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ background: "var(--tc-input)" }}>
              <Th>{fr ? "Email" : "Email"}</Th>
              <Th>{fr ? "Nom" : "Name"}</Th>
              <Th>{fr ? "Rôle" : "Role"}</Th>
              <Th>{fr ? "Statut" : "Status"}</Th>
              <Th>{fr ? "Remédiation" : "Remediation"}</Th>
              <Th> </Th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} style={{ borderTop: "1px solid var(--tc-border)" }}>
                <Td><span style={{ fontWeight: 600 }}>{u.email}</span></Td>
                <Td>{u.display_name}</Td>
                <Td>
                  <select
                    value={u.role}
                    onChange={(e) => patchUser(u, { role: e.target.value })}
                    style={{ ...inputStyle, width: "auto", padding: "4px 8px" }}
                  >
                    {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </Td>
                <Td>
                  <span style={{ color: u.status === "active" ? "#30a050" : u.status === "invited" ? "#d09020" : "var(--tc-text-muted)" }}>
                    {u.status === "active" ? (fr ? "Actif" : "Active") : u.status === "invited" ? (fr ? "Invité" : "Invited") : (fr ? "Désactivé" : "Disabled")}
                  </span>
                </Td>
                <Td>
                  {u.role === "analyst" ? (
                    <input type="checkbox" checked={u.can_remediate} onChange={(e) => patchUser(u, { canRemediate: e.target.checked })} />
                  ) : (
                    <span style={{ color: "var(--tc-text-muted)" }}>{u.role === "admin" ? (fr ? "Oui" : "Yes") : "—"}</span>
                  )}
                </Td>
                <Td>
                  <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                    {u.status !== "invited" && (
                      <button style={btnGhost} title={u.status === "active" ? (fr ? "Désactiver" : "Disable") : (fr ? "Activer" : "Enable")}
                        onClick={() => patchUser(u, { status: u.status === "active" ? "disabled" : "active" })}>
                        {u.status === "active" ? (fr ? "Désactiver" : "Disable") : (fr ? "Activer" : "Enable")}
                      </button>
                    )}
                    {u.status === "invited" && (
                      <button style={btnGhost} title={fr ? "Renvoyer l'invitation" : "Resend invite"} onClick={() => regen(u, "reinvite")}>
                        <RotateCcw size={13} />
                      </button>
                    )}
                    <button style={btnGhost} title={fr ? "Réinitialiser le mot de passe" : "Reset password"} onClick={() => regen(u, "reset-password")}>
                      <KeyRound size={13} />
                    </button>
                    <button style={{ ...btnGhost, color: "#d03020" }} title={fr ? "Supprimer" : "Delete"} onClick={() => deleteUser(u)}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                </Td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr><Td colSpan={6}><span style={{ color: "var(--tc-text-muted)" }}>{fr ? "Aucun utilisateur" : "No users"}</span></Td></tr>
            )}
          </tbody>
        </table>
      </div>

      {showInvite && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }} onClick={closeInvite}>
          <div style={{ ...cardStyle, width: 440, maxWidth: "90vw", marginBottom: 0 }} onClick={(e) => e.stopPropagation()}>
            <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 16 }}>{fr ? "Inviter un utilisateur" : "Invite a user"}</div>
            {invLink ? (
              <div>
                <div style={{ fontSize: 12, color: "var(--tc-text-muted)", marginBottom: 8 }}>
                  {fr ? "Email non configuré. Transmettez ce lien à la personne :" : "Email not configured. Share this link with the person:"}
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <input readOnly style={inputStyle} value={`${window.location.origin}${invLink}`}
                    onFocus={(e) => e.currentTarget.select()} />
                  <button style={btnGhost} onClick={async () => { setCopied(await copyText(`${window.location.origin}${invLink}`)); }}>
                    {copied ? <CheckCircle size={14} color="#30a050" /> : <Copy size={14} />}
                    {copied ? (fr ? "Copié" : "Copied") : ""}
                  </button>
                </div>
                <div style={{ marginTop: 16, textAlign: "right" }}>
                  <button style={btnPrimary} onClick={closeInvite}>{fr ? "Fermer" : "Close"}</button>
                </div>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <div>
                  <div style={labelStyle}>{fr ? "Email" : "Email"}</div>
                  <input style={inputStyle} value={invEmail} onChange={(e) => setInvEmail(e.target.value)} />
                </div>
                <div>
                  <div style={labelStyle}>{fr ? "Nom affiché" : "Display name"}</div>
                  <input style={inputStyle} value={invName} onChange={(e) => setInvName(e.target.value)} />
                </div>
                <div>
                  <div style={labelStyle}>{fr ? "Rôle" : "Role"}</div>
                  <select style={inputStyle} value={invRole} onChange={(e) => setInvRole(e.target.value)}>
                    {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
                {invRole === "analyst" && (
                  <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
                    <input type="checkbox" checked={invRemediate} onChange={(e) => setInvRemediate(e.target.checked)} />
                    {fr ? "Autoriser la remédiation" : "Allow remediation"}
                  </label>
                )}
                <div>
                  <div style={labelStyle}>{fr ? "Votre mot de passe (confirmation)" : "Your password (confirmation)"}</div>
                  <input type="password" style={inputStyle} value={invPw} onChange={(e) => setInvPw(e.target.value)} autoComplete="current-password" />
                </div>
                {invErr && <div style={{ fontSize: 12, color: "#d03020" }}>{invErr}</div>}
                <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 4 }}>
                  <button style={btnGhost} onClick={closeInvite}>{fr ? "Annuler" : "Cancel"}</button>
                  <button style={btnPrimary} onClick={submitInvite} disabled={invBusy}>
                    {invBusy ? <Loader2 size={14} className="animate-spin" /> : <UserPlus size={14} />}
                    {fr ? "Inviter" : "Invite"}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// Robust copy: the Clipboard API needs a secure context and is often blocked
// behind a self-signed cert, so fall back to a temporary textarea + execCommand.
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to legacy path */
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

function Th({ children }: { children: React.ReactNode }) {
  return <th style={{ textAlign: "left", padding: "10px 14px", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--tc-text-muted)" }}>{children}</th>;
}
function Td({ children, colSpan }: { children: React.ReactNode; colSpan?: number }) {
  return <td colSpan={colSpan} style={{ padding: "10px 14px", color: "var(--tc-text)" }}>{children}</td>;
}
