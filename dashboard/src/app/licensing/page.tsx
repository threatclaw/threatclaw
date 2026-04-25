"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Key, Clock, AlertTriangle, CheckCircle2, RefreshCw, Power, Mail, Loader2 } from "lucide-react";
import { NeuCard } from "@/components/chrome/NeuCard";

// Mirror of the Rust `LicenseStatus` struct exposed by /api/tc/licensing/status.
interface LicenseStatus {
  provisioned: boolean;
  license_key: string | null;
  licensee_email: string | null;
  tier: "trial" | "individual" | "action_pack" | "msp" | "enterprise" | null;
  skills: string[];
  grace: { kind: string; days_remaining?: number; days_into_grace?: number; days_left_in_grace?: number } | null;
  trial: boolean;
  expires_at: number | null;
  last_heartbeat: number;
  last_attempt: number;
  trial_consumed: boolean;
}

const TIER_LABELS: Record<string, string> = {
  trial: "Essai 60 jours",
  individual: "Individual",
  action_pack: "Action Pack",
  msp: "MSP",
  enterprise: "Enterprise",
};

function formatTimestamp(ts: number | null): string {
  if (!ts || ts === 0) return "—";
  return new Date(ts * 1000).toLocaleString("fr-FR");
}

function formatDate(ts: number | null): string {
  if (!ts || ts === 0) return "—";
  return new Date(ts * 1000).toLocaleDateString("fr-FR");
}

export default function LicensingPage() {
  const [status, setStatus] = useState<LicenseStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  // Activation form
  const [licenseKey, setLicenseKey] = useState("");

  // Trial form
  const [trialEmail, setTrialEmail] = useState("");
  const [trialOrg, setTrialOrg] = useState("");
  const [trialSkill, setTrialSkill] = useState("skill-velociraptor-actions");

  const fetchStatus = useCallback(async () => {
    try {
      const r = await fetch("/api/tc/licensing/status", { cache: "no-store" });
      if (!r.ok) throw new Error(await r.text());
      setStatus(await r.json());
    } catch (e: any) {
      setError(`Impossible de charger le statut : ${e?.message ?? e}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const flash = (msg: string, isErr = false) => {
    if (isErr) {
      setError(msg);
      setInfo(null);
    } else {
      setInfo(msg);
      setError(null);
    }
    setTimeout(() => { setError(null); setInfo(null); }, 6000);
  };

  // Server returns "kind:message" on rejection so we can present a friendly hint.
  const friendlyError = (raw: string): string => {
    const colon = raw.indexOf(":");
    if (colon < 0) return raw;
    const kind = raw.slice(0, colon);
    const message = raw.slice(colon + 1);
    const hints: Record<string, string> = {
      not_found: "Cette clé de licence n'existe pas. Vérifiez la saisie.",
      unauthenticated: "Cette clé n'est pas reconnue. Vérifiez la saisie.",
      subscription_inactive: "Votre abonnement est inactif (impayé ou annulé). Renouvelez sur le portail.",
      revoked: "Cette licence a été révoquée. Contactez le support.",
      activation_limit: "Toutes les activations sont utilisées. Désactivez un autre site dans le portail puis réessayez.",
      trial_already_used: "Un essai a déjà été consommé pour cet email ou cette installation.",
      bad_request: "Données invalides — vérifiez les champs.",
      rate_limit: "Trop de tentatives. Patientez quelques minutes.",
    };
    return hints[kind] ?? message;
  };

  const post = async <T,>(path: string, body?: unknown): Promise<T | null> => {
    setBusy(true);
    try {
      const r = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      const text = await r.text();
      if (!r.ok) {
        flash(friendlyError(text), true);
        return null;
      }
      return text ? JSON.parse(text) : null;
    } catch (e: any) {
      flash(`Erreur réseau : ${e?.message ?? e}`, true);
      return null;
    } finally {
      setBusy(false);
    }
  };

  const onActivate = async () => {
    const key = licenseKey.trim();
    if (!key) return flash("Saisissez une clé de licence.", true);
    const newStatus = await post<LicenseStatus>("/api/tc/licensing/activate", { license_key: key });
    if (newStatus) {
      setStatus(newStatus);
      setLicenseKey("");
      flash("Licence activée avec succès.");
    }
  };

  const onStartTrial = async () => {
    if (!trialEmail.includes("@")) return flash("Email invalide.", true);
    if (!trialSkill.trim()) return flash("Choisissez un skill.", true);
    const newStatus = await post<LicenseStatus>("/api/tc/licensing/trial/start", {
      email: trialEmail.trim(),
      org: trialOrg.trim(),
      skill: trialSkill.trim(),
    });
    if (newStatus) {
      setStatus(newStatus);
      flash(`Essai démarré — clé envoyée à ${trialEmail.trim()}.`);
    }
  };

  const onHeartbeat = async () => {
    const r = await post<{ status: LicenseStatus; message: string }>("/api/tc/licensing/heartbeat");
    if (r) {
      setStatus(r.status);
      flash(r.message);
    }
  };

  const onDeactivate = async () => {
    if (!confirm("Désactiver la licence sur cette installation ? Le slot sera libéré côté serveur — vous pourrez l'activer ailleurs.")) return;
    const r = await post<{ message: string }>("/api/tc/licensing/deactivate");
    if (r) {
      await fetchStatus();
      flash(r.message);
    }
  };

  if (loading) {
    return <div style={{ padding: 32 }}><Loader2 className="animate-spin" /> Chargement...</div>;
  }

  const hasLicense = !!status?.license_key;

  return (
    <div style={{ padding: 24, maxWidth: 960, margin: "0 auto", display: "flex", flexDirection: "column", gap: 20 }}>
      <header>
        <h1 style={{ fontSize: 24, fontWeight: 600, margin: 0, marginBottom: 4 }}>Licence Premium</h1>
        <p style={{ margin: 0, color: "var(--tc-grey-mid)", fontSize: 14 }}>
          Activation des skills d'action premium (remédiation, quarantaine endpoint, blocage firewall…).
          Le cœur ThreatClaw reste gratuit AGPL.
        </p>
      </header>

      {error && (
        <div style={{ padding: 12, background: "rgba(208,48,32,0.10)", border: "1px solid rgba(208,48,32,0.3)", borderRadius: 6, color: "#d03020" }}>
          <AlertTriangle size={14} style={{ display: "inline", marginRight: 8 }} />
          {error}
        </div>
      )}
      {info && (
        <div style={{ padding: 12, background: "rgba(48,160,80,0.10)", border: "1px solid rgba(48,160,80,0.3)", borderRadius: 6, color: "#30a050" }}>
          <CheckCircle2 size={14} style={{ display: "inline", marginRight: 8 }} />
          {info}
        </div>
      )}

      {!status?.provisioned && (
        <NeuCard accent="amber">
          <div style={{ padding: 20 }}>
            <strong>Licensing non provisionné dans cette build.</strong>
            <p style={{ margin: "8px 0 0", fontSize: 13, color: "var(--tc-grey-mid)" }}>
              L'infrastructure de licence (clé Ed25519) n'est pas encore intégrée à ce binaire.
              Aucun skill premium ne peut être activé tant que la cérémonie de signature n'a pas été effectuée.
            </p>
          </div>
        </NeuCard>
      )}

      {/* ── Licence active ─────────────────────────────────────── */}
      {hasLicense && status?.provisioned && (
        <NeuCard accent={status.grace?.kind === "lapsed" ? "red" : status.grace?.kind === "in_grace" ? "amber" : "green"}>
          <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Key size={18} />
              <strong>Licence active</strong>
              {status.tier && (
                <span style={{ fontSize: 12, padding: "2px 8px", background: "rgba(208,48,32,0.12)", border: "1px solid rgba(208,48,32,0.25)", borderRadius: 4, color: "#d03020" }}>
                  {TIER_LABELS[status.tier] ?? status.tier}
                </span>
              )}
              {status.trial && (
                <span style={{ fontSize: 12, padding: "2px 8px", background: "rgba(48,128,208,0.12)", border: "1px solid rgba(48,128,208,0.25)", borderRadius: 4, color: "#3080d0" }}>
                  ESSAI
                </span>
              )}
            </div>

            <table style={{ fontSize: 13, borderSpacing: 0 }}>
              <tbody>
                <tr><td style={{ padding: "4px 12px 4px 0", color: "var(--tc-grey-mid)" }}>Clé</td>
                    <td style={{ fontFamily: "monospace" }}>{status.license_key}</td></tr>
                <tr><td style={{ padding: "4px 12px 4px 0", color: "var(--tc-grey-mid)" }}>Email</td>
                    <td>{status.licensee_email ?? "—"}</td></tr>
                <tr><td style={{ padding: "4px 12px 4px 0", color: "var(--tc-grey-mid)" }}>Skills débloqués</td>
                    <td>{status.skills.length === 0 ? "—" : status.skills.join(", ")}</td></tr>
                <tr><td style={{ padding: "4px 12px 4px 0", color: "var(--tc-grey-mid)" }}>Expire le</td>
                    <td>{formatDate(status.expires_at)}</td></tr>
                <tr><td style={{ padding: "4px 12px 4px 0", color: "var(--tc-grey-mid)" }}>Dernier heartbeat</td>
                    <td>{formatTimestamp(status.last_heartbeat)}</td></tr>
              </tbody>
            </table>

            {status.grace?.kind === "renewal_soon" && (
              <div style={{ padding: 10, fontSize: 13, background: "rgba(208,144,32,0.10)", borderRadius: 4, color: "#b8801a" }}>
                <Clock size={14} style={{ display: "inline", marginRight: 6 }} />
                Renouvellement dans {status.grace.days_remaining} jour(s).
              </div>
            )}
            {status.grace?.kind === "in_grace" && (
              <div style={{ padding: 10, fontSize: 13, background: "rgba(208,48,32,0.10)", borderRadius: 4, color: "#d03020" }}>
                <AlertTriangle size={14} style={{ display: "inline", marginRight: 6 }} />
                Licence expirée — période de grâce ({status.grace.days_left_in_grace} jour(s) restant(s)).
                Renouvelez dès que possible pour éviter la coupure des skills premium.
              </div>
            )}

            <div style={{ display: "flex", gap: 10, marginTop: 4 }}>
              <button onClick={onHeartbeat} disabled={busy}
                style={btnSecondary}>
                <RefreshCw size={14} /> Rafraîchir maintenant
              </button>
              <button onClick={onDeactivate} disabled={busy}
                style={btnDanger}>
                <Power size={14} /> Désactiver ce site
              </button>
            </div>
          </div>
        </NeuCard>
      )}

      {/* ── Aucune licence : activer ────────────────────────────── */}
      {!hasLicense && status?.provisioned && (
        <>
          <NeuCard accent="blue">
            <div style={{ padding: 20 }}>
              <h2 style={{ margin: 0, marginBottom: 6, fontSize: 16 }}>
                <Key size={16} style={{ display: "inline", marginRight: 8 }} />
                J'ai une clé de licence
              </h2>
              <p style={{ margin: "0 0 12px", fontSize: 13, color: "var(--tc-grey-mid)" }}>
                Collez la clé reçue par mail (format <code>TC-XXXX-XXXX-XXXX-XXXX</code>).
              </p>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  type="text"
                  value={licenseKey}
                  onChange={(e) => setLicenseKey(e.target.value)}
                  placeholder="TC-AP24-X7K9-M2P4-VN5R"
                  style={inputStyle}
                  spellCheck={false}
                />
                <button onClick={onActivate} disabled={busy} style={btnPrimary}>
                  Activer
                </button>
              </div>
            </div>
          </NeuCard>

          <NeuCard accent={status.trial_consumed ? "amber" : "green"}>
            <div style={{ padding: 20 }}>
              <h2 style={{ margin: 0, marginBottom: 6, fontSize: 16 }}>
                <Mail size={16} style={{ display: "inline", marginRight: 8 }} />
                Essayer gratuitement 60 jours
              </h2>
              <p style={{ margin: "0 0 12px", fontSize: 13, color: "var(--tc-grey-mid)" }}>
                {status.trial_consumed ? (
                  <>Un essai a déjà été démarré sur cette installation. Vous pouvez réessayer mais le serveur peut refuser.</>
                ) : (
                  <>1 skill premium au choix, sans carte bancaire. Une clé vous sera envoyée par mail.</>
                )}
              </p>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
                <input type="email" placeholder="email@boite.fr" value={trialEmail}
                  onChange={(e) => setTrialEmail(e.target.value)} style={inputStyle} />
                <input type="text" placeholder="Nom organisation (optionnel)" value={trialOrg}
                  onChange={(e) => setTrialOrg(e.target.value)} style={inputStyle} />
              </div>
              <select value={trialSkill} onChange={(e) => setTrialSkill(e.target.value)}
                style={{ ...inputStyle, marginBottom: 8 }}>
                <option value="skill-velociraptor-actions">Velociraptor Actions (quarantaine endpoint)</option>
                <option value="skill-opnsense-actions">OPNsense Actions (block IP / kill states)</option>
                <option value="skill-fortinet-actions">Fortinet Actions</option>
                <option value="skill-ad-remediation">AD Remediation (disable / reset password)</option>
              </select>
              <button onClick={onStartTrial} disabled={busy} style={btnPrimary}>
                Démarrer l'essai 60 jours
              </button>
            </div>
          </NeuCard>
        </>
      )}

      {/* ── Footer diagnostic ──────────────────────────────────── */}
      <div style={{ fontSize: 11, color: "var(--tc-grey-mid)", paddingTop: 8, borderTop: "1px solid var(--tc-border)" }}>
        Provisioned: {String(status?.provisioned)} · Last attempt: {formatTimestamp(status?.last_attempt ?? 0)}
        {status?.trial_consumed && " · Trial consumed"}
      </div>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  flex: 1, padding: "8px 10px", fontSize: 13, fontFamily: "inherit",
  background: "var(--tc-bg-input)", border: "1px solid var(--tc-border)",
  borderRadius: 4, color: "var(--tc-text)",
};

const btnBase: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", gap: 6,
  padding: "8px 14px", fontSize: 13, fontWeight: 500,
  borderRadius: 4, cursor: "pointer", border: "1px solid transparent",
};

const btnPrimary: React.CSSProperties = {
  ...btnBase,
  background: "var(--tc-red)", color: "#fff", borderColor: "var(--tc-red)",
};

const btnSecondary: React.CSSProperties = {
  ...btnBase,
  background: "var(--tc-bg-input)", color: "var(--tc-text)", borderColor: "var(--tc-border)",
};

const btnDanger: React.CSSProperties = {
  ...btnBase,
  background: "transparent", color: "#d03020", borderColor: "rgba(208,48,32,0.4)",
};
