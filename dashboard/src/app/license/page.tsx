"use client";

// Unified License & Instance page.
//
// Replaces the legacy /licensing (Action Pack copy) and the old
// /setup?tab=about. Single canonical place for everything an operator
// needs about this install:
//
//   1. Instance — install_id, version, hostname, last sync
//   2. Plan    — tier, asset count vs cap, expires, license_key,
//                Refresh / Manage subscription / Manage activations
//   3. Activate — paste license_key (visible only when no active license)
//   4. Air-gap — paste cert (collapsed by default)
//   5. Account — email + password change
//   6. Support — pre-filled support button
//
// Wires:
//   GET  /api/tc/license                     — instance_id + version
//   GET  /api/tc/licensing/status            — list of active licenses
//   GET  /api/tc/admin/billing-status       — current billable count
//   GET  /api/auth/me                        — logged-in user email
//   POST /api/tc/licensing/activate          — paste license_key
//   POST /api/tc/licensing/heartbeat         — refresh cert ("Refresh now")
//   POST /api/tc/licensing/portal-session    — Stripe billing portal URL
//   POST /api/tc/licensing/deactivate        — release this slot
//   POST /api/auth/password                  — change password

import React, { useCallback, useEffect, useState } from "react";
import {
  Copy,
  RefreshCw,
  ExternalLink,
  AlertTriangle,
  CheckCircle2,
  ServerCog,
  KeyRound,
  Loader2,
  ChevronDown,
  ChevronUp,
  MessageSquare,
  Lock,
} from "lucide-react";
import { useLocale } from "@/lib/useLocale";

// ── Types ────────────────────────────────────────────────────────────

interface InstanceInfo {
  instance_id?: string;
  version?: string;
  hostname?: string;
}

interface ActiveLicense {
  license_key: string;
  licensee_email: string;
  tier: string;
  skills: string[];
  grace: { kind: string; days_remaining?: number; days_into_grace?: number; days_left_in_grace?: number };
  trial: boolean;
  expires_at: number;
  last_heartbeat: number;
  last_attempt: number;
  active?: boolean;
}

interface LicenseStatus {
  provisioned: boolean;
  licenses: ActiveLicense[];
  trial_consumed: boolean;
}

interface BillingStatusResponse {
  count: { billable: number; total: number; computed_at: string; error?: string };
  billing: {
    tier: string;
    assets_limit: number | null;
    current_count: number;
    has_cert: boolean;
    expires_at: number | null;
    state:
      | { kind: "within_limit" }
      | { kind: "approaching"; remaining: number }
      | { kind: "over_limit"; over_by: number }
      | { kind: "unlimited" };
  };
}

interface AuthMe {
  authenticated: boolean;
  user?: { email: string };
}

// ── Helpers ──────────────────────────────────────────────────────────

const TIER_LABELS: Record<string, { fr: string; en: string }> = {
  free: { fr: "Free", en: "Free" },
  trial: { fr: "Essai 60 jours", en: "60-day trial" },
  starter: { fr: "Starter", en: "Starter" },
  individual: { fr: "Starter (legacy)", en: "Starter (legacy)" },
  action_pack: { fr: "Starter (legacy)", en: "Starter (legacy)" },
  pro: { fr: "Pro", en: "Pro" },
  business: { fr: "Business", en: "Business" },
  msp: { fr: "MSP", en: "MSP" },
  enterprise: { fr: "Enterprise", en: "Enterprise" },
};

function tierLabel(tier: string, locale: string): string {
  return TIER_LABELS[tier]?.[locale === "fr" ? "fr" : "en"] ?? tier;
}

function formatDate(ts: number | null | undefined, locale: string): string {
  if (!ts || ts === 0) return "—";
  return new Date(ts * 1000).toLocaleDateString(locale === "fr" ? "fr-FR" : "en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatDateTime(ts: number | null | undefined, locale: string): string {
  if (!ts || ts === 0) return "—";
  return new Date(ts * 1000).toLocaleString(locale === "fr" ? "fr-FR" : "en-US");
}

function formatRelative(ts: number, locale: string): string {
  if (!ts) return "—";
  const ageSecs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  const fr = locale === "fr";
  if (ageSecs < 60) return fr ? "à l'instant" : "just now";
  if (ageSecs < 3600) return fr ? `il y a ${Math.floor(ageSecs / 60)} min` : `${Math.floor(ageSecs / 60)} min ago`;
  if (ageSecs < 86400) return fr ? `il y a ${Math.floor(ageSecs / 3600)} h` : `${Math.floor(ageSecs / 3600)} h ago`;
  return fr ? `il y a ${Math.floor(ageSecs / 86400)} j` : `${Math.floor(ageSecs / 86400)} d ago`;
}

function gaugeColor(ratio: number): string {
  if (ratio >= 1) return "#e04040";
  if (ratio >= 0.9) return "#d09020";
  return "#30a050";
}

// ── Page ─────────────────────────────────────────────────────────────

export default function LicensePage() {
  const locale = useLocale();
  const fr = locale === "fr";

  const [instance, setInstance] = useState<InstanceInfo | null>(null);
  const [licenseStatus, setLicenseStatus] = useState<LicenseStatus | null>(null);
  const [billing, setBilling] = useState<BillingStatusResponse | null>(null);
  const [user, setUser] = useState<AuthMe["user"] | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [activateKey, setActivateKey] = useState("");
  const [airgapOpen, setAirgapOpen] = useState(false);
  const [airgapCert, setAirgapCert] = useState("");
  const [pwd, setPwd] = useState({ current: "", next: "" });
  const [pwdMsg, setPwdMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // ── Polling ────────────────────────────────────────────────────────

  const refresh = useCallback(async () => {
    try {
      const [instRes, statusRes, billingRes, meRes] = await Promise.all([
        fetch("/api/tc/license").then((r) => (r.ok ? r.json() : null)).catch(() => null),
        fetch("/api/tc/licensing/status").then((r) => (r.ok ? r.json() : null)).catch(() => null),
        fetch("/api/tc/admin/billing-status").then((r) => (r.ok ? r.json() : null)).catch(() => null),
        fetch("/api/auth/me").then((r) => (r.ok ? r.json() : null)).catch(() => null),
      ]);
      setInstance(instRes ?? null);
      setLicenseStatus(statusRes ?? null);
      setBilling(billingRes ?? null);
      setUser((meRes as AuthMe | null)?.user ?? null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 30_000);
    return () => clearInterval(iv);
  }, [refresh]);

  // ── Actions ────────────────────────────────────────────────────────

  const copy = (value: string, field: string) => {
    navigator.clipboard.writeText(value);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 1500);
  };

  const activate = async () => {
    setError(null);
    setInfo(null);
    setBusy("activate");
    try {
      const res = await fetch("/api/tc/licensing/activate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ license_key: activateKey.trim() }),
      });
      if (!res.ok) {
        setError(await res.text() || (fr ? "Activation refusée" : "Activation refused"));
      } else {
        setInfo(fr ? "Licence activée. Cert installé." : "License activated. Cert installed.");
        setActivateKey("");
        await refresh();
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    }
    setBusy(null);
  };

  const heartbeat = async (license_key?: string) => {
    setError(null);
    setInfo(null);
    setBusy(`heartbeat:${license_key ?? "all"}`);
    try {
      const res = await fetch("/api/tc/licensing/heartbeat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(license_key ? { license_key } : {}),
      });
      if (!res.ok) {
        setError(await res.text() || (fr ? "Refresh impossible" : "Refresh failed"));
      } else {
        setInfo(fr ? "Cert rafraîchi depuis le serveur de licence." : "Cert refreshed from the license server.");
        await refresh();
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    }
    setBusy(null);
  };

  const openBillingPortal = async (license_key: string) => {
    setError(null);
    setBusy(`portal:${license_key}`);
    try {
      const res = await fetch("/api/tc/licensing/portal-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          license_key,
          return_url: window.location.origin + "/license",
        }),
      });
      if (!res.ok) {
        setError(await res.text() || (fr ? "Impossible d'ouvrir le portail" : "Could not open portal"));
      } else {
        const data = (await res.json()) as { url: string };
        window.open(data.url, "_blank", "noopener,noreferrer");
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    }
    setBusy(null);
  };

  const openCustomerPortal = () => {
    const email = user?.email ?? licenseStatus?.licenses?.[0]?.licensee_email ?? "";
    const url = email
      ? `https://account.threatclaw.io/?email=${encodeURIComponent(email)}`
      : "https://account.threatclaw.io/";
    window.open(url, "_blank", "noopener,noreferrer");
  };

  const deactivate = async (license_key: string) => {
    if (!confirm(
      fr
        ? `Désactiver la licence ${license_key.slice(0, 12)}… sur cet install ?\n\nLa slot d'activation sera libérée côté serveur. Les actions HITL ne seront plus disponibles tant qu'une licence n'est pas réactivée ici.`
        : `Deactivate license ${license_key.slice(0, 12)}… on this install?\n\nThe activation slot is released server-side. HITL actions will be denied until a license is reactivated here.`,
    )) {
      return;
    }
    setError(null);
    setBusy(`deactivate:${license_key}`);
    try {
      const res = await fetch("/api/tc/licensing/deactivate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ license_key }),
      });
      if (!res.ok) {
        setError(await res.text() || (fr ? "Désactivation impossible" : "Deactivation failed"));
      } else {
        setInfo(fr ? "Licence désactivée localement et côté serveur." : "License deactivated locally and on the server.");
        await refresh();
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    }
    setBusy(null);
  };

  const applyAirgapCert = async () => {
    // The air-gap cert paste reuses the same activate endpoint with a
    // special flag the agent inspects (server treats a base64 .tcl
    // envelope as a pre-issued cert and skips the worker round-trip).
    setError(null);
    setInfo(null);
    setBusy("airgap");
    try {
      const res = await fetch("/api/tc/licensing/activate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ license_key: airgapCert.trim() }),
      });
      if (!res.ok) {
        setError(await res.text() || (fr ? "Cert refusé" : "Cert refused"));
      } else {
        setInfo(fr ? "Cert installé en mode air-gapped." : "Air-gapped cert installed.");
        setAirgapCert("");
        await refresh();
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    }
    setBusy(null);
  };

  const changePassword = async () => {
    setPwdMsg(null);
    if (!pwd.current || !pwd.next) {
      setPwdMsg({ ok: false, text: fr ? "Champs requis" : "Both fields required" });
      return;
    }
    setBusy("password");
    try {
      const res = await fetch("/api/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: pwd.current, newPassword: pwd.next }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) {
        setPwdMsg({ ok: false, text: data.error || (fr ? "Refus" : "Refused") });
      } else {
        setPwdMsg({ ok: true, text: fr ? "Mot de passe changé." : "Password changed." });
        setPwd({ current: "", next: "" });
      }
    } catch (e: any) {
      setPwdMsg({ ok: false, text: String(e?.message || e) });
    }
    setBusy(null);
  };

  const openSupport = () => {
    const params = new URLSearchParams();
    const primary = licenseStatus?.licenses?.[0];
    if (primary) params.set("license_key", primary.license_key);
    if (instance?.instance_id) params.set("instance_id", instance.instance_id);
    if (instance?.version) params.set("version", instance.version);
    window.open(`https://threatclaw.io/${locale}/support?${params.toString()}`, "_blank", "noopener,noreferrer");
  };

  // ── Derived values ─────────────────────────────────────────────────

  const primary = licenseStatus?.licenses?.[0];
  const hasLicense = !!primary;
  const billable = billing?.count?.billable ?? 0;
  const assetsLimit = billing?.billing?.assets_limit ?? null;
  const tierFromBilling = billing?.billing?.tier ?? "free";
  const tier = primary?.tier ?? tierFromBilling;
  const ratio = assetsLimit && assetsLimit > 0 ? Math.min(1, billable / assetsLimit) : 0;
  const ratioPct = ratio * 100;
  const overLimit = billing?.billing?.state?.kind === "over_limit";

  // ── Render ─────────────────────────────────────────────────────────

  return (
    <div
      style={{
        padding: "24px 28px",
        maxWidth: "1100px",
        margin: "0 auto",
        color: "var(--tc-text)",
        fontFamily: "'JetBrains Mono', ui-monospace, monospace",
      }}
    >
      <h1 style={{ fontSize: "20px", fontWeight: 800, marginBottom: "4px" }}>
        {fr ? "Licence & instance" : "License & instance"}
      </h1>
      <p style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "20px" }}>
        {fr
          ? "Tout ce que tu as besoin de savoir sur cette installation et sur ta licence ThreatClaw."
          : "Everything you need to know about this install and your ThreatClaw license."}
      </p>

      {error && (
        <div style={banner("error")}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}
      {info && (
        <div style={banner("info")}>
          <CheckCircle2 size={14} /> {info}
        </div>
      )}

      {/* ── 1. Cette installation ── */}
      <section style={cardStyle()}>
        <h2 style={sectionTitle()}>
          <ServerCog size={14} /> {fr ? "Cette installation" : "This install"}
        </h2>
        <Row label={fr ? "Instance ID" : "Instance ID"}>
          <Mono value={instance?.instance_id ?? "…"} field="instance" copiedField={copiedField} onCopy={copy} />
        </Row>
        <Row label="Version">
          <span style={{ fontFamily: "monospace", fontSize: "13px", fontWeight: 700 }}>
            {instance?.version ?? "…"}
          </span>
        </Row>
        {instance?.hostname && (
          <Row label="Hostname">
            <span style={{ fontFamily: "monospace", fontSize: "12px" }}>{instance.hostname}</span>
          </Row>
        )}
        <Row label={fr ? "Licence cœur" : "Core license"}>
          <span style={{ color: "var(--tc-green)", fontWeight: 700, fontSize: "12px" }}>
            AGPL v3 + Commercial
          </span>
        </Row>
        {primary && (
          <Row label={fr ? "Dernière sync" : "Last sync"}>
            <span style={{ fontSize: "12px", color: "var(--tc-text-sec)" }}>
              {formatRelative(primary.last_heartbeat, locale)}
            </span>
          </Row>
        )}
      </section>

      {/* ── 2. Plan actuel ── */}
      <section style={cardStyle()}>
        <h2 style={sectionTitle()}>
          <KeyRound size={14} /> {fr ? "Plan actuel" : "Current plan"}
        </h2>

        <div
          style={{
            display: "flex",
            alignItems: "baseline",
            gap: "12px",
            marginBottom: "16px",
          }}
        >
          <span
            style={{
              fontSize: "20px",
              fontWeight: 800,
              color: hasLicense ? "var(--tc-text)" : "var(--tc-text-muted)",
            }}
          >
            {tierLabel(tier, locale).toUpperCase()}
          </span>
          {primary?.trial && (
            <span style={pillStyle("#d09020")}>
              {fr ? "Essai" : "Trial"}
            </span>
          )}
          {primary && (
            <span style={pillStyle(primary.active ? "#30a050" : "#888")}>
              {primary.active ? (fr ? "Actif" : "Active") : (fr ? "Inactif" : "Inactive")}
            </span>
          )}
        </div>

        {/* Asset gauge */}
        <div style={{ marginBottom: "12px" }}>
          <div
            style={{
              display: "flex",
              alignItems: "baseline",
              justifyContent: "space-between",
              fontSize: "11px",
              color: "var(--tc-text-sec)",
              marginBottom: "6px",
            }}
          >
            <span>
              <strong style={{ fontSize: "16px", color: gaugeColor(ratio), fontFamily: "monospace" }}>
                {billable}
              </strong>
              {" / "}
              {assetsLimit == null ? "∞" : assetsLimit}{" "}
              {fr ? "assets facturables" : "billable assets"}
            </span>
            {assetsLimit != null && (
              <span style={{ color: "var(--tc-text-muted)" }}>
                {ratioPct.toFixed(0)}%
              </span>
            )}
          </div>
          {assetsLimit != null && (
            <div
              style={{
                height: "8px",
                background: "var(--tc-input)",
                borderRadius: "4px",
                overflow: "hidden",
                border: "1px solid var(--tc-border)",
              }}
            >
              <div
                style={{
                  width: `${Math.max(0, Math.min(100, ratioPct))}%`,
                  height: "100%",
                  background: gaugeColor(ratio),
                  transition: "width 600ms ease, background 200ms",
                }}
              />
            </div>
          )}
        </div>

        {overLimit && (
          <div style={banner("error", { marginBottom: "12px" })}>
            <AlertTriangle size={14} />{" "}
            {fr
              ? `Tu dépasses ton cap de ${assetsLimit} assets. Upgrade à un tier supérieur pour rester couvert.`
              : `You exceed your ${assetsLimit}-asset cap. Upgrade to a higher tier to stay covered.`}
          </div>
        )}
        {ratio >= 0.9 && ratio < 1 && (
          <div style={banner("warn", { marginBottom: "12px" })}>
            <AlertTriangle size={14} />{" "}
            {fr
              ? `${(ratioPct).toFixed(0)} % du cap atteint. Considère le tier supérieur avant la saturation.`
              : `${(ratioPct).toFixed(0)}% of cap reached. Consider upgrading before saturation.`}
          </div>
        )}

        {primary && (
          <>
            <Row label={fr ? "Renouvellement" : "Renews"}>
              <span style={{ fontSize: "12px" }}>{formatDate(primary.expires_at, locale)}</span>
            </Row>
            <Row label={fr ? "Clé licence" : "License key"}>
              <Mono value={primary.license_key} field="license_key" copiedField={copiedField} onCopy={copy} />
            </Row>
            {primary.licensee_email && (
              <Row label="Contact">
                <span style={{ fontSize: "12px", fontFamily: "monospace" }}>{primary.licensee_email}</span>
              </Row>
            )}

            {/* Action buttons */}
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "8px",
                marginTop: "16px",
                paddingTop: "16px",
                borderTop: "1px solid var(--tc-border)",
              }}
            >
              <ActionButton
                onClick={() => heartbeat(primary.license_key)}
                busy={busy === `heartbeat:${primary.license_key}`}
                icon={<RefreshCw size={12} />}
                label={fr ? "Refresh now" : "Refresh now"}
              />
              <ActionButton
                onClick={() => openBillingPortal(primary.license_key)}
                busy={busy === `portal:${primary.license_key}`}
                icon={<ExternalLink size={12} />}
                label={fr ? "Manage subscription" : "Manage subscription"}
              />
              <ActionButton
                onClick={openCustomerPortal}
                icon={<ExternalLink size={12} />}
                label={fr ? "Manage activations" : "Manage activations"}
              />
              <ActionButton
                onClick={() => deactivate(primary.license_key)}
                busy={busy === `deactivate:${primary.license_key}`}
                icon={<Lock size={12} />}
                label={fr ? "Désactiver ici" : "Deactivate here"}
                danger
              />
            </div>
          </>
        )}
      </section>

      {/* ── 3. Activate license_key (visible if no active license) ── */}
      {!hasLicense && !loading && (
        <section style={cardStyle()}>
          <h2 style={sectionTitle()}>
            <KeyRound size={14} /> {fr ? "Pas encore de licence ?" : "No license yet?"}
          </h2>
          <p style={{ fontSize: "12px", color: "var(--tc-text-sec)", marginBottom: "12px" }}>
            {fr ? (
              <>
                Achète ton plan sur{" "}
                <a
                  href="https://threatclaw.io/fr/pricing"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: "var(--tc-blue)" }}
                >
                  threatclaw.io/pricing
                </a>{" "}
                puis colle la clé reçue par email ci-dessous.
              </>
            ) : (
              <>
                Buy a plan on{" "}
                <a
                  href="https://threatclaw.io/en/pricing"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: "var(--tc-blue)" }}
                >
                  threatclaw.io/pricing
                </a>{" "}
                then paste the key you received by email below.
              </>
            )}
          </p>
          <textarea
            value={activateKey}
            onChange={(e) => setActivateKey(e.target.value)}
            placeholder={fr ? "Colle ta license key ici" : "Paste your license key here"}
            rows={2}
            style={textareaStyle()}
          />
          <div style={{ marginTop: "8px" }}>
            <ActionButton
              onClick={activate}
              busy={busy === "activate"}
              disabled={!activateKey.trim()}
              icon={<KeyRound size={12} />}
              label={fr ? "Activer" : "Activate"}
              primary
            />
          </div>
        </section>
      )}

      {/* ── 4. Air-gapped install (collapsible) ── */}
      <section style={cardStyle()}>
        <button
          onClick={() => setAirgapOpen(!airgapOpen)}
          style={{
            width: "100%",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            background: "transparent",
            border: "none",
            cursor: "pointer",
            color: "var(--tc-text)",
            padding: 0,
            fontFamily: "inherit",
          }}
        >
          <h2 style={{ ...sectionTitle(), margin: 0 }}>
            <Lock size={14} /> {fr ? "Installation air-gapped" : "Air-gapped install"}
          </h2>
          {airgapOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
        {airgapOpen && (
          <div style={{ marginTop: "12px" }}>
            <p style={{ fontSize: "12px", color: "var(--tc-text-sec)", marginBottom: "12px" }}>
              {fr
                ? "Pour les installations sans accès Internet sortant. Récupère ton certificat sur account.threatclaw.io (depuis un poste connecté) puis colle-le ici. La signature Ed25519 est vérifiée localement."
                : "For installs with no outbound internet. Fetch your certificate from account.threatclaw.io (from a connected machine) then paste it here. The Ed25519 signature is verified locally."}
            </p>
            <textarea
              value={airgapCert}
              onChange={(e) => setAirgapCert(e.target.value)}
              placeholder={fr ? "Colle le certificat (.tcl base64)" : "Paste the certificate (.tcl base64)"}
              rows={4}
              style={textareaStyle()}
            />
            <div style={{ marginTop: "8px" }}>
              <ActionButton
                onClick={applyAirgapCert}
                busy={busy === "airgap"}
                disabled={!airgapCert.trim()}
                icon={<KeyRound size={12} />}
                label={fr ? "Appliquer le cert" : "Apply cert"}
              />
            </div>
          </div>
        )}
      </section>

      {/* ── 5. Mon compte ── */}
      {user && (
        <section style={cardStyle()}>
          <h2 style={sectionTitle()}>
            <Lock size={14} /> {fr ? "Mon compte" : "My account"}
          </h2>
          <Row label={fr ? "Email" : "Email"}>
            <span style={{ fontSize: "12px", fontFamily: "monospace" }}>{user.email}</span>
          </Row>
          <div style={{ marginTop: "12px" }}>
            <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "6px" }}>
              {fr ? "Changer le mot de passe" : "Change password"}
            </div>
            <input
              type="password"
              value={pwd.current}
              onChange={(e) => setPwd({ ...pwd, current: e.target.value })}
              placeholder={fr ? "Mot de passe actuel" : "Current password"}
              style={inputStyle()}
            />
            <input
              type="password"
              value={pwd.next}
              onChange={(e) => setPwd({ ...pwd, next: e.target.value })}
              placeholder={fr ? "Nouveau mot de passe" : "New password"}
              style={{ ...inputStyle(), marginTop: "6px" }}
            />
            <div style={{ marginTop: "8px", display: "flex", alignItems: "center", gap: "8px" }}>
              <ActionButton
                onClick={changePassword}
                busy={busy === "password"}
                disabled={!pwd.current || !pwd.next}
                icon={<RefreshCw size={12} />}
                label={fr ? "Mettre à jour" : "Update"}
              />
              {pwdMsg && (
                <span style={{ fontSize: "11px", color: pwdMsg.ok ? "var(--tc-green)" : "#e04040" }}>
                  {pwdMsg.text}
                </span>
              )}
            </div>
          </div>
        </section>
      )}

      {/* ── 6. Support ── */}
      <section style={cardStyle()}>
        <h2 style={sectionTitle()}>
          <MessageSquare size={14} /> Support
        </h2>
        <p style={{ fontSize: "12px", color: "var(--tc-text-sec)", margin: "0 0 12px" }}>
          {fr
            ? "Le bouton ci-dessous ouvre threatclaw.io/support avec ton Instance ID et ta License key pré-remplis pour un traitement prioritaire."
            : "The button below opens threatclaw.io/support pre-filled with your Instance ID and license key for priority routing."}
        </p>
        <ActionButton
          onClick={openSupport}
          icon={<MessageSquare size={12} />}
          label={fr ? "Ouvrir un ticket support" : "Open a support ticket"}
        />
      </section>
    </div>
  );
}

// ── Sub-components ───────────────────────────────────────────────────

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "6px 0",
        borderBottom: "1px solid var(--tc-border)",
      }}
    >
      <span style={{ fontSize: "10px", color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>
        {label}
      </span>
      <div style={{ textAlign: "right" }}>{children}</div>
    </div>
  );
}

function Mono({
  value,
  field,
  copiedField,
  onCopy,
}: {
  value: string;
  field: string;
  copiedField: string | null;
  onCopy: (v: string, f: string) => void;
}) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}>
      <span style={{ fontFamily: "monospace", fontSize: "12px", color: "var(--tc-text)" }}>{value}</span>
      <button
        onClick={() => onCopy(value, field)}
        title="Copier"
        style={{
          padding: "2px 6px",
          fontSize: "10px",
          border: "1px solid var(--tc-border)",
          borderRadius: "3px",
          background: "var(--tc-input)",
          color: "var(--tc-text-muted)",
          cursor: "pointer",
          fontFamily: "inherit",
        }}
      >
        {copiedField === field ? "✓" : <Copy size={10} />}
      </button>
    </span>
  );
}

function ActionButton({
  onClick,
  busy,
  disabled,
  icon,
  label,
  primary,
  danger,
}: {
  onClick: () => void;
  busy?: boolean;
  disabled?: boolean;
  icon: React.ReactNode;
  label: string;
  primary?: boolean;
  danger?: boolean;
}) {
  const bg = primary ? "var(--tc-blue)" : danger ? "rgba(224,64,64,0.1)" : "var(--tc-input)";
  const color = primary ? "#fff" : danger ? "#e04040" : "var(--tc-text)";
  const border = primary ? "var(--tc-blue)" : danger ? "rgba(224,64,64,0.4)" : "var(--tc-border)";
  return (
    <button
      onClick={onClick}
      disabled={disabled || busy}
      style={{
        padding: "6px 12px",
        fontSize: "11px",
        fontWeight: 600,
        fontFamily: "inherit",
        border: `1px solid ${border}`,
        background: bg,
        color,
        borderRadius: "3px",
        cursor: disabled || busy ? "not-allowed" : "pointer",
        opacity: disabled || busy ? 0.6 : 1,
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
      }}
    >
      {busy ? <Loader2 size={12} className="animate-spin" /> : icon}
      {label}
    </button>
  );
}

// ── Style helpers ────────────────────────────────────────────────────

function cardStyle(): React.CSSProperties {
  return {
    background: "var(--tc-bg)",
    border: "1px solid var(--tc-border)",
    borderRadius: "var(--tc-radius-md)",
    padding: "16px 20px",
    marginBottom: "16px",
  };
}

function sectionTitle(): React.CSSProperties {
  return {
    fontSize: "12px",
    fontWeight: 700,
    color: "var(--tc-text)",
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    margin: "0 0 12px",
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
  };
}

function pillStyle(color: string): React.CSSProperties {
  return {
    fontSize: "10px",
    fontWeight: 700,
    padding: "2px 8px",
    background: `${color}18`,
    border: `1px solid ${color}40`,
    color,
    borderRadius: "3px",
    textTransform: "uppercase",
    letterSpacing: "0.05em",
  };
}

function inputStyle(): React.CSSProperties {
  return {
    width: "100%",
    padding: "8px 10px",
    fontSize: "12px",
    fontFamily: "monospace",
    border: "1px solid var(--tc-border)",
    borderRadius: "3px",
    background: "var(--tc-input)",
    color: "var(--tc-text)",
  };
}

function textareaStyle(): React.CSSProperties {
  return {
    ...inputStyle(),
    resize: "vertical",
  };
}

function banner(kind: "error" | "info" | "warn", extra: React.CSSProperties = {}): React.CSSProperties {
  const palette = {
    error: { bg: "rgba(224,64,64,0.08)", border: "rgba(224,64,64,0.3)", color: "#e04040" },
    warn: { bg: "rgba(208,144,32,0.08)", border: "rgba(208,144,32,0.3)", color: "#d09020" },
    info: { bg: "rgba(48,160,80,0.08)", border: "rgba(48,160,80,0.3)", color: "#30a050" },
  }[kind];
  return {
    display: "inline-flex",
    alignItems: "center",
    gap: "8px",
    padding: "8px 12px",
    fontSize: "12px",
    background: palette.bg,
    border: `1px solid ${palette.border}`,
    color: palette.color,
    borderRadius: "3px",
    marginBottom: "12px",
    width: "100%",
    boxSizing: "border-box",
    ...extra,
  };
}
