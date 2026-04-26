"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Key, Clock, AlertTriangle, CheckCircle2, RefreshCw, Power, Mail, Loader2, Plus, MessageSquare } from "lucide-react";
import { NeuCard } from "@/components/chrome/NeuCard";

// Mirror of the Rust `LicenseStatus` struct exposed by /api/tc/licensing/status.
interface ActiveLicense {
  license_key: string;
  licensee_email: string;
  tier: "trial" | "individual" | "action_pack" | "msp" | "enterprise";
  skills: string[];
  grace: { kind: string; days_remaining?: number; days_into_grace?: number; days_left_in_grace?: number };
  trial: boolean;
  expires_at: number;
  last_heartbeat: number;
  last_attempt: number;
}

interface LicenseStatus {
  provisioned: boolean;
  licenses: ActiveLicense[];
  trial_consumed: boolean;
}

const TIER_LABELS: Record<string, string> = {
  trial: "Essai 60 jours",
  individual: "Individual",
  action_pack: "Action Pack",
  msp: "MSP",
  enterprise: "Enterprise",
};

const SKILL_LABELS: Record<string, string> = {
  // Doctrine pivot 2026-04-26: a single Action Pack license unlocks
  // every HITL destructive flow across all connectors. The legacy
  // per-skill ids below are still understood by older certs in the
  // wild and are mapped to the same human label.
  "hitl": "Action Pack — Toutes les actions HITL",
  "skill-velociraptor-actions": "Action Pack (legacy: velociraptor)",
  "skill-opnsense-actions": "Action Pack (legacy: opnsense)",
  "skill-fortinet-actions": "Action Pack (legacy: fortinet)",
  "skill-ad-remediation": "Action Pack (legacy: ad-remediation)",
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
  const [busy, setBusy] = useState<string | null>(null); // license_key being acted on, or "global"
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  // Activation form
  const [licenseKey, setLicenseKey] = useState("");
  const [showAddForm, setShowAddForm] = useState(false);

  // Trial form
  const [trialEmail, setTrialEmail] = useState("");
  const [trialOrg, setTrialOrg] = useState("");
  const [trialSkill, setTrialSkill] = useState("hitl");
  const [showTrialForm, setShowTrialForm] = useState(false);

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

  useEffect(() => { fetchStatus(); }, [fetchStatus]);

  const flash = (msg: string, isErr = false) => {
    if (isErr) { setError(msg); setInfo(null); }
    else { setInfo(msg); setError(null); }
    setTimeout(() => { setError(null); setInfo(null); }, 6000);
  };

  const friendlyError = (raw: string): string => {
    const colon = raw.indexOf(":");
    if (colon < 0) return raw;
    const kind = raw.slice(0, colon);
    const message = raw.slice(colon + 1);
    const hints: Record<string, string> = {
      not_found: "Cette clé de licence n'existe pas. Vérifiez la saisie.",
      unauthenticated: "Cette clé n'est pas reconnue.",
      subscription_inactive: "Votre abonnement est inactif (impayé ou annulé).",
      revoked: "Cette licence a été révoquée. Contactez le support.",
      activation_limit: "Toutes les activations sont utilisées. Désactivez un autre site puis réessayez (ou contactez le support si vous venez de réinstaller).",
      trial_already_used: "Un essai a déjà été consommé pour cet email ou cette installation.",
      bad_request: "Données invalides — vérifiez les champs.",
      rate_limit: "Trop de tentatives. Patientez quelques minutes.",
    };
    return hints[kind] ?? message;
  };

  const post = async <T,>(path: string, body?: unknown): Promise<T | null> => {
    try {
      const r = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      const text = await r.text();
      if (!r.ok) { flash(friendlyError(text), true); return null; }
      return text ? JSON.parse(text) : null;
    } catch (e: any) {
      flash(`Erreur réseau : ${e?.message ?? e}`, true);
      return null;
    }
  };

  const onActivate = async () => {
    const key = licenseKey.trim();
    if (!key) return flash("Saisissez une clé de licence.", true);
    setBusy("global");
    const newStatus = await post<LicenseStatus>("/api/tc/licensing/activate", { license_key: key });
    setBusy(null);
    if (newStatus) {
      setStatus(newStatus);
      setLicenseKey("");
      setShowAddForm(false);
      flash("Licence activée avec succès.");
    }
  };

  const onStartTrial = async () => {
    if (!trialEmail.includes("@")) return flash("Email invalide.", true);
    if (!trialSkill.trim()) return flash("Choisissez un skill.", true);
    setBusy("global");
    const newStatus = await post<LicenseStatus>("/api/tc/licensing/trial/start", {
      email: trialEmail.trim(),
      org: trialOrg.trim(),
      skill: trialSkill.trim(),
    });
    setBusy(null);
    if (newStatus) {
      setStatus(newStatus);
      setShowTrialForm(false);
      flash(`Essai démarré — clé envoyée à ${trialEmail.trim()}.`);
    }
  };

  const onHeartbeat = async (key: string) => {
    setBusy(key);
    const r = await post<{ status: LicenseStatus; message: string }>("/api/tc/licensing/heartbeat", { license_key: key });
    setBusy(null);
    if (r) { setStatus(r.status); flash(r.message); }
  };

  const onDeactivate = async (key: string) => {
    if (!confirm(`Désactiver la licence ${key} sur cette installation ?\n\nLe slot sera libéré côté serveur — vous pourrez l'activer ailleurs.`)) return;
    setBusy(key);
    const r = await post<{ status: LicenseStatus; message: string }>("/api/tc/licensing/deactivate", { license_key: key });
    setBusy(null);
    if (r) { setStatus(r.status); flash(r.message); }
  };

  const openSupport = (license_key?: string) => {
    const params = new URLSearchParams();
    if (license_key) params.set("license_key", license_key);
    params.set("version", "1.0.x-beta");
    const url = `https://threatclaw.io/support?${params.toString()}`;
    window.open(url, "_blank", "noopener");
  };

  if (loading) {
    return <div style={{ padding: 32 }}><Loader2 className="animate-spin" /> Chargement...</div>;
  }

  const licenses = status?.licenses ?? [];
  const hasAny = licenses.length > 0;
  const totalSkills = licenses.flatMap(l => l.skills).filter(s => s !== "*").length;
  const hasWildcard = licenses.some(l => l.skills.includes("*"));

  return (
    <div style={{ padding: 24, maxWidth: 960, margin: "0 auto", display: "flex", flexDirection: "column", gap: 16 }}>
      <header>
        <h1 style={{ fontSize: 24, fontWeight: 600, margin: 0, marginBottom: 4 }}>Mes licences</h1>
        <p style={{ margin: 0, color: "var(--tc-grey-mid)", fontSize: 14 }}>
          ThreatClaw reste gratuit en AGPL pour toute la collecte, l&apos;analyse et la détection.
          La licence <strong>Action Pack</strong> ajoute l&apos;exécution des actions HITL destructives
          (block IP, désactiver compte, isoler endpoint, …) avec workflow d&apos;approbation, audit log
          signé et notification Slack/email.
        </p>
      </header>

      {error && (
        <div style={{ padding: 12, background: "rgba(208,48,32,0.10)", border: "1px solid rgba(208,48,32,0.3)", borderRadius: 6, color: "#d03020" }}>
          <AlertTriangle size={14} style={{ display: "inline", marginRight: 8 }} />{error}
        </div>
      )}
      {info && (
        <div style={{ padding: 12, background: "rgba(48,160,80,0.10)", border: "1px solid rgba(48,160,80,0.3)", borderRadius: 6, color: "#30a050" }}>
          <CheckCircle2 size={14} style={{ display: "inline", marginRight: 8 }} />{info}
        </div>
      )}

      {!status?.provisioned && (
        <NeuCard accent="amber">
          <div style={{ padding: 20 }}>
            <strong>Licensing non provisionné dans cette build.</strong>
            <p style={{ margin: "8px 0 0", fontSize: 13, color: "var(--tc-grey-mid)" }}>
              Aucune licence ne peut être activée tant que la cérémonie de signature n&apos;a pas été effectuée.
            </p>
          </div>
        </NeuCard>
      )}

      {/* ── No-license CTA ───────────────────────────────────────────── */}
      {status?.provisioned && !hasAny && (
        <div style={{
          padding: 14, borderRadius: 6,
          background: "rgba(48,128,208,0.06)", border: "1px solid rgba(48,128,208,0.22)",
          fontSize: 13, color: "var(--tc-text)", lineHeight: 1.55,
        }}>
          Tu n&apos;as pas encore de licence active. La détection / corrélation / propositions L2
          fonctionnent déjà avec la version Community gratuite. Pour <strong>exécuter</strong> les
          actions HITL proposées (bloquer une IP sur le firewall, désactiver un compte AD, isoler
          un endpoint via Velociraptor, etc.), il te faut un Action Pack actif.
          {' '}<a href="https://threatclaw.io/fr/pricing" target="_blank" rel="noreferrer" style={{ color: "var(--tc-red)", fontWeight: 600 }}>
            Voir les tarifs
          </a>
          {' '}ou démarre un essai 60 jours gratuit ci-dessous.
        </div>
      )}

      {/* ── Existing licenses ────────────────────────────────────────── */}
      {hasAny && licenses.map((license) => {
        const accent = license.grace?.kind === "lapsed" ? "red" : license.grace?.kind === "in_grace" ? "amber" : "green";
        const skillNames = license.skills.map(s => s === "*" ? "Tous les skills premium" : (SKILL_LABELS[s] ?? s)).join(", ");
        return (
          <NeuCard key={license.license_key} accent={accent}>
            <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <Key size={18} />
                <strong>{license.licensee_email || "Licence active"}</strong>
                <span style={{ fontSize: 12, padding: "2px 8px", background: "rgba(208,48,32,0.12)", border: "1px solid rgba(208,48,32,0.25)", borderRadius: 4, color: "#d03020" }}>
                  {TIER_LABELS[license.tier] ?? license.tier}
                </span>
                {license.trial && (
                  <span style={{ fontSize: 12, padding: "2px 8px", background: "rgba(48,128,208,0.12)", border: "1px solid rgba(48,128,208,0.25)", borderRadius: 4, color: "#3080d0" }}>
                    ESSAI
                  </span>
                )}
              </div>

              <table style={{ fontSize: 13, borderSpacing: 0 }}>
                <tbody>
                  <tr><td style={{ padding: "3px 12px 3px 0", color: "var(--tc-grey-mid)", whiteSpace: "nowrap" }}>Clé</td>
                      <td style={{ fontFamily: "monospace" }}>{license.license_key}</td></tr>
                  <tr><td style={{ padding: "3px 12px 3px 0", color: "var(--tc-grey-mid)", whiteSpace: "nowrap" }}>Skills débloqués</td>
                      <td>{skillNames || "—"}</td></tr>
                  <tr><td style={{ padding: "3px 12px 3px 0", color: "var(--tc-grey-mid)", whiteSpace: "nowrap" }}>Expire le</td>
                      <td>{formatDate(license.expires_at)}</td></tr>
                  <tr><td style={{ padding: "3px 12px 3px 0", color: "var(--tc-grey-mid)", whiteSpace: "nowrap" }}>Dernier heartbeat</td>
                      <td>{formatTimestamp(license.last_heartbeat)}</td></tr>
                </tbody>
              </table>

              {license.grace?.kind === "renewal_soon" && (
                <div style={{ padding: 10, fontSize: 13, background: "rgba(208,144,32,0.10)", borderRadius: 4, color: "#b8801a" }}>
                  <Clock size={14} style={{ display: "inline", marginRight: 6 }} />
                  Renouvellement dans {license.grace.days_remaining} jour(s).
                </div>
              )}
              {license.grace?.kind === "in_grace" && (
                <div style={{ padding: 10, fontSize: 13, background: "rgba(208,48,32,0.10)", borderRadius: 4, color: "#d03020" }}>
                  <AlertTriangle size={14} style={{ display: "inline", marginRight: 6 }} />
                  Licence expirée — période de grâce ({license.grace.days_left_in_grace} j restants).
                </div>
              )}

              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button onClick={() => onHeartbeat(license.license_key)} disabled={busy !== null} style={btnSecondary}>
                  {busy === license.license_key ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                  Rafraîchir
                </button>
                <button onClick={() => onDeactivate(license.license_key)} disabled={busy !== null} style={btnDanger}>
                  <Power size={14} /> Désactiver
                </button>
                <button onClick={() => openSupport(license.license_key)} style={btnGhost}>
                  <MessageSquare size={14} /> Contacter support
                </button>
              </div>
            </div>
          </NeuCard>
        );
      })}

      {/* ── Add a new license / start trial ─────────────────────────── */}
      {status?.provisioned && (
        <NeuCard accent="blue">
          <div style={{ padding: 20 }}>
            {!hasAny && !showAddForm && !showTrialForm && (
              <p style={{ margin: "0 0 12px", fontSize: 14 }}>
                Aucune licence active sur cette installation. Vous pouvez :
              </p>
            )}
            {hasAny && !showAddForm && !showTrialForm && (
              <p style={{ margin: "0 0 12px", fontSize: 14 }}>
                Vous avez acheté une autre licence ? Activez sa clé ici.
              </p>
            )}

            {!showAddForm && !showTrialForm && (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button onClick={() => setShowAddForm(true)} style={btnPrimary}>
                  <Plus size={14} /> Ajouter une clé de licence
                </button>
                {!status?.trial_consumed && (
                  <button onClick={() => setShowTrialForm(true)} style={btnSecondary}>
                    <Mail size={14} /> Démarrer un essai 60 jours
                  </button>
                )}
              </div>
            )}

            {showAddForm && (
              <div>
                <h3 style={{ margin: "0 0 6px", fontSize: 15 }}>
                  <Key size={14} style={{ display: "inline", marginRight: 6 }} />
                  Activer une clé de licence
                </h3>
                <p style={{ margin: "0 0 12px", fontSize: 13, color: "var(--tc-grey-mid)" }}>
                  Collez la clé reçue par mail (format <code>TC-XXXX-XXXX-XXXX-XXXX</code>).
                </p>
                <div style={{ display: "flex", gap: 8 }}>
                  <input type="text" value={licenseKey} onChange={(e) => setLicenseKey(e.target.value)}
                    placeholder="TC-AP24-X7K9-M2P4-VN5R" style={inputStyle} spellCheck={false} autoFocus />
                  <button onClick={onActivate} disabled={busy !== null} style={btnPrimary}>
                    {busy === "global" ? <Loader2 size={14} className="animate-spin" /> : null} Activer
                  </button>
                  <button onClick={() => { setShowAddForm(false); setLicenseKey(""); }} style={btnGhost}>
                    Annuler
                  </button>
                </div>
              </div>
            )}

            {showTrialForm && (
              <div>
                <h3 style={{ margin: "0 0 6px", fontSize: 15 }}>
                  <Mail size={14} style={{ display: "inline", marginRight: 6 }} />
                  Essai Action Pack — 60 jours gratuits
                </h3>
                <p style={{ margin: "0 0 12px", fontSize: 13, color: "var(--tc-grey-mid)" }}>
                  Action Pack complet sans carte bancaire (toutes les actions HITL débloquées :
                  block IP firewall, désactiver compte AD, isoler endpoint Velociraptor…). Une clé
                  arrive par mail.
                </p>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
                  <input type="email" placeholder="email@boite.fr" value={trialEmail}
                    onChange={(e) => setTrialEmail(e.target.value)} style={inputStyle} />
                  <input type="text" placeholder="Nom organisation (optionnel)" value={trialOrg}
                    onChange={(e) => setTrialOrg(e.target.value)} style={inputStyle} />
                </div>
                {/* No skill picker any more — Action Pack is the single SKU. */}
                <input type="hidden" value={trialSkill} readOnly />
                <div style={{ display: "flex", gap: 8 }}>
                  <button onClick={onStartTrial} disabled={busy !== null} style={btnPrimary}>
                    {busy === "global" ? <Loader2 size={14} className="animate-spin" /> : null} Démarrer l'essai
                  </button>
                  <button onClick={() => setShowTrialForm(false)} style={btnGhost}>Annuler</button>
                </div>
              </div>
            )}
          </div>
        </NeuCard>
      )}

      {/* ── Footer hints ─────────────────────────────────────────────── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: 8, borderTop: "1px solid var(--tc-border)", fontSize: 11, color: "var(--tc-grey-mid)" }}>
        <span>
          Provisioned: {String(status?.provisioned)} ·
          {status?.trial_consumed ? " Essai consommé" : " Essai disponible"}
        </span>
        <a href="https://threatclaw.io/fr/pricing" target="_blank" rel="noreferrer"
           style={{ color: "var(--tc-grey-mid)", textDecoration: "underline" }}>
          Voir tous les plans →
        </a>
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

const btnPrimary: React.CSSProperties = { ...btnBase, background: "var(--tc-red)", color: "#fff", borderColor: "var(--tc-red)" };
const btnSecondary: React.CSSProperties = { ...btnBase, background: "var(--tc-bg-input)", color: "var(--tc-text)", borderColor: "var(--tc-border)" };
const btnDanger: React.CSSProperties = { ...btnBase, background: "transparent", color: "#d03020", borderColor: "rgba(208,48,32,0.4)" };
const btnGhost: React.CSSProperties = { ...btnBase, background: "transparent", color: "var(--tc-grey-mid)", borderColor: "var(--tc-border)" };
