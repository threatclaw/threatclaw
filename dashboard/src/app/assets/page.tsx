"use client";

import React, { useState, useEffect, useCallback } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import {
  Server, Monitor, Smartphone, Globe, Network, Printer, Cpu, Factory, Cloud, HelpCircle,
  Plus, Search, Settings, Trash2, X, RefreshCw, Loader2, Shield, ChevronRight, ChevronLeft,
  AlertTriangle, Eye, CheckCircle2, Wifi, Upload, Download,
} from "lucide-react";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { PageShell } from "@/components/chrome/PageShell";

// ── Types ──

interface Asset {
  id: string; name: string; category: string; subcategory: string | null;
  role: string | null; criticality: string; ip_addresses: string[];
  mac_address: string | null; hostname: string | null; fqdn: string | null;
  url: string | null; os: string | null; os_confidence: number;
  mac_vendor: string | null; services: any; source: string; status: string;
  last_seen: string; first_seen: string; owner: string | null;
  location: string | null; tags: string[]; notes: string | null;
  classification_method: string; classification_confidence: number;
  // V67 — billable filter dimension.
  inventory_status?: string;
  distinct_days_seen_30d?: number;
  billable_status?: string;
  demo?: boolean;
  sources?: string[];
  // V68 — single-toggle exclusion (billing + monitoring).
  excluded?: boolean;
  exclusion_reason?: string;
  exclusion_until?: string | null;
  exclusion_by?: string;
}

interface Category {
  id: string; label: string; label_en: string | null; icon: string;
  color: string; subcategories: string[]; is_builtin: boolean;
}

// V67 — billable filter buckets.
type BillableFilter = "all" | "billable" | "observation" | "duplicates" | "inactive";

const BILLABLE_FILTERS: Array<{
  id: BillableFilter;
  labelFr: string;
  labelEn: string;
  predicate: (a: Asset) => boolean;
}> = [
  { id: "all", labelFr: "Tous", labelEn: "All", predicate: () => true },
  {
    id: "billable",
    labelFr: "Facturables",
    labelEn: "Billable",
    predicate: (a) =>
      !a.demo &&
      a.status === "active" &&
      a.inventory_status !== "inactive" &&
      (a.inventory_status === "declared" ||
        a.inventory_status === "observed_persistent" ||
        (a.inventory_status === "observed_transient" &&
          (a.distinct_days_seen_30d ?? 0) >= 3)),
  },
  {
    id: "observation",
    labelFr: "En observation",
    labelEn: "In observation",
    predicate: (a) =>
      a.inventory_status === "observed_transient" &&
      (a.distinct_days_seen_30d ?? 0) < 3 &&
      a.status === "active",
  },
  {
    id: "duplicates",
    labelFr: "Doublons probables",
    labelEn: "Probable duplicates",
    predicate: (a) => a.classification_confidence < 0.5,
  },
  {
    id: "inactive",
    labelFr: "Inactifs",
    labelEn: "Inactive",
    predicate: (a) => a.inventory_status === "inactive" || (a.status !== "active" && a.status !== "merged"),
  },
];

// Extra opt-in filter (one-shot, separate from the 5 main BILLABLE_FILTERS).
// Used to surface manually-excluded assets which are otherwise hidden by
// 'all' (because excluded → not billable, not in observation, not inactive
// per V67 rules — they live in their own bucket).
const EXTRA_FILTERS: Array<{
  id: BillableFilter | "excluded" | "merged";
  labelFr: string;
  labelEn: string;
  predicate: (a: Asset) => boolean;
}> = [
  {
    id: "excluded",
    labelFr: "Exclus",
    labelEn: "Excluded",
    predicate: (a) => a.excluded === true,
  },
  {
    id: "merged",
    labelFr: "Fusionnés",
    labelEn: "Merged",
    predicate: (a) => a.status === "merged",
  },
];

const INVENTORY_BADGE: Record<string, { labelFr: string; labelEn: string; color: string }> = {
  declared: { labelFr: "Déclaré", labelEn: "Declared", color: "#30a050" },
  observed_persistent: { labelFr: "Observé · réseau", labelEn: "Observed · network", color: "#4080d0" },
  observed_transient: { labelFr: "En observation", labelEn: "In observation", color: "#d09020" },
  inactive: { labelFr: "Inactif", labelEn: "Inactive", color: "#888" },
};

// ── Constants ──

const ICON_MAP: Record<string, React.ElementType> = {
  server: Server, monitor: Monitor, smartphone: Smartphone, globe: Globe,
  network: Network, printer: Printer, cpu: Cpu, factory: Factory,
  cloud: Cloud, "help-circle": HelpCircle,
};

const CRIT_COLORS: Record<string, { color: string; label: string }> = {
  critical: { color: "#e04040", label: "Critique" },
  high: { color: "#d07020", label: "Haut" },
  medium: { color: "#d09020", label: "Moyen" },
  low: { color: "#30a050", label: "Bas" },
};

const CAT_DESCRIPTIONS: Record<string, string> = {
  server: "Serveurs physiques ou virtuels (web, base de données, mail, AD...)",
  workstation: "Postes de travail fixes, laptops, tablettes",
  mobile: "Smartphones et tablettes",
  website: "Sites web, applications SaaS, APIs",
  network: "Firewalls, switches, routeurs, bornes WiFi",
  printer: "Imprimantes, scanners, copieurs réseau",
  iot: "Caméras, badges, capteurs, objets connectés",
  ot: "Automates industriels, SCADA, HMI",
  cloud: "VMs cloud, containers, fonctions serverless",
  unknown: "Devices détectés automatiquement, en attente de classification",
};

// ── Styles ──

const cardStyle: React.CSSProperties = {
  background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-md)", padding: "20px",
};

const inputStyle: React.CSSProperties = {
  width: "100%", padding: "8px 10px", fontSize: "11px", fontFamily: "inherit",
  background: "var(--tc-input)", border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-sm)", color: "var(--tc-text)", outline: "none",
};

const labelStyle: React.CSSProperties = {
  fontSize: "9px", fontWeight: 700, color: "var(--tc-text-muted)",
  textTransform: "uppercase" as const, letterSpacing: "0.05em", marginBottom: "3px", display: "block",
};

const btnPrimary: React.CSSProperties = {
  background: "var(--tc-red)", color: "#fff", border: "none", borderRadius: "var(--tc-radius-md)",
  padding: "10px 20px", fontSize: "12px", fontWeight: 700, cursor: "pointer", fontFamily: "inherit",
  display: "inline-flex", alignItems: "center", gap: "6px",
};

const btnSecondary: React.CSSProperties = {
  background: "var(--tc-input)", color: "var(--tc-text-sec)", border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-md)", padding: "8px 14px", fontSize: "11px", fontWeight: 600,
  cursor: "pointer", fontFamily: "inherit", display: "inline-flex", alignItems: "center", gap: "4px",
};

// ── Component ──

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#e84040", HIGH: "#d07020", MEDIUM: "var(--tc-amber)", LOW: "var(--tc-blue)",
};

// V68 — exclusion + merge ops panel rendered at the bottom of the asset
// detail modal. Single source of truth for "this asset shouldn't be
// counted or analysed any more" and "this asset is a duplicate of
// another, redirect future events to it".
function ExclusionPanel({ asset, onChanged }: { asset: Asset; onChanged: () => void }) {
  const locale = useLocale();
  const fr = locale === "fr";

  const [busy, setBusy] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [info, setInfo] = React.useState<string | null>(null);

  // Confirm-and-reason modal state for the destructive 'exclude' toggle.
  const [showExcludeModal, setShowExcludeModal] = React.useState(false);
  const [reason, setReason] = React.useState("");
  const [days, setDays] = React.useState(90);

  const isExcluded = !!asset.excluded;

  const submitExclusion = async (excluded: boolean) => {
    setError(null);
    setInfo(null);
    setBusy("exclude");
    try {
      const res = await fetch(`/api/tc/assets/${asset.id}/exclude`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ excluded, reason, days }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        setError(data.error || (fr ? "Refus" : "Refused"));
      } else {
        setInfo(
          excluded
            ? fr
              ? `Asset exclu (auto-expire dans ${days} j si > 0).`
              : `Asset excluded (auto-expire in ${days} d if > 0).`
            : fr
            ? "Exclusion levée. L'asset reprend la facturation et la surveillance."
            : "Exclusion lifted. Asset returns to billing and monitoring."
        );
        setShowExcludeModal(false);
        setReason("");
        onChanged();
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    }
    setBusy(null);
  };

  const liftExclusion = () => submitExclusion(false);

  return (
    <div
      style={{
        marginTop: "16px",
        padding: "14px 16px",
        background: "var(--tc-input)",
        border: "1px solid var(--tc-border)",
        borderRadius: "var(--tc-radius-sm)",
      }}
    >
      <div
        style={{
          fontSize: "10px",
          fontWeight: 700,
          color: "var(--tc-text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: "10px",
        }}
      >
        {fr ? "Statut commercial" : "Commercial status"}
      </div>

      {error && (
        <div
          style={{
            padding: "6px 10px",
            background: "rgba(208,48,32,0.08)",
            border: "1px solid rgba(208,48,32,0.3)",
            color: "#d03020",
            fontSize: "11px",
            borderRadius: "3px",
            marginBottom: "10px",
          }}
        >
          {error}
        </div>
      )}
      {info && (
        <div
          style={{
            padding: "6px 10px",
            background: "rgba(48,160,80,0.08)",
            border: "1px solid rgba(48,160,80,0.3)",
            color: "#30a050",
            fontSize: "11px",
            borderRadius: "3px",
            marginBottom: "10px",
          }}
        >
          {info}
        </div>
      )}

      {isExcluded ? (
        <div>
          <div
            style={{
              padding: "10px 12px",
              background: "rgba(208,48,32,0.08)",
              border: "1px solid rgba(208,48,32,0.4)",
              borderRadius: "3px",
              marginBottom: "10px",
              fontSize: "12px",
              color: "#d03020",
            }}
          >
            <strong>{fr ? "Cet asset est EXCLU" : "This asset is EXCLUDED"}</strong>
            <div style={{ fontSize: "11px", color: "var(--tc-text-sec)", marginTop: "6px", lineHeight: 1.5 }}>
              {fr
                ? "Pas comptabilisé dans la facturation. Aucun nouveau finding/alert n'est traité dessus. Restitué dans /assets uniquement via le filtre 'Exclus'."
                : "Not counted toward billing. No new finding/alert is processed against it. Visible only via the 'Excluded' filter."}
            </div>
            {asset.exclusion_reason && (
              <div style={{ fontSize: "11px", marginTop: "8px" }}>
                {fr ? "Raison : " : "Reason: "}
                <em>{asset.exclusion_reason}</em>
              </div>
            )}
            {asset.exclusion_until && (
              <div style={{ fontSize: "11px", marginTop: "4px", color: "var(--tc-text-muted)" }}>
                {fr ? "Auto-expire le " : "Auto-expires "}
                {new Date(asset.exclusion_until).toLocaleString(fr ? "fr-FR" : "en-US")}
              </div>
            )}
            {asset.exclusion_by && (
              <div style={{ fontSize: "10px", marginTop: "4px", color: "var(--tc-text-muted)" }}>
                {fr ? "Exclu par : " : "Excluded by: "}
                {asset.exclusion_by}
              </div>
            )}
          </div>
          <button
            onClick={liftExclusion}
            disabled={busy === "exclude"}
            style={{
              padding: "6px 14px",
              fontSize: "11px",
              fontWeight: 600,
              fontFamily: "inherit",
              border: "1px solid var(--tc-border)",
              background: "var(--tc-input)",
              color: "var(--tc-text)",
              borderRadius: "3px",
              cursor: "pointer",
            }}
          >
            {busy === "exclude" ? "…" : fr ? "Lever l'exclusion" : "Lift exclusion"}
          </button>
        </div>
      ) : (
        <div>
          <p style={{ fontSize: "12px", color: "var(--tc-text-sec)", margin: "0 0 12px", lineHeight: 1.5 }}>
            {fr
              ? "Exclure cet asset = il n'est plus compté dans la facturation ET ThreatClaw arrête de l'analyser. À utiliser pour : honeypot dédié, asset partenaire visible mais pas à toi, capteur bruyant à museler, équipement en transition."
              : "Excluding this asset = no longer counted toward billing AND ThreatClaw stops analysing it. Use for: dedicated honeypot, third-party visible asset, noisy sensor to mute, transitioning gear."}
          </p>
          <button
            onClick={() => setShowExcludeModal(true)}
            style={{
              padding: "6px 14px",
              fontSize: "11px",
              fontWeight: 600,
              fontFamily: "inherit",
              border: "1px solid rgba(208,48,32,0.4)",
              background: "rgba(208,48,32,0.06)",
              color: "#d03020",
              borderRadius: "3px",
              cursor: "pointer",
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
            }}
          >
            <AlertTriangle size={12} /> {fr ? "Exclure cet asset" : "Exclude this asset"}
          </button>
        </div>
      )}

      {/* ── Exclude confirmation modal (destructive action) ── */}
      {showExcludeModal && (
        <div
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowExcludeModal(false);
          }}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.65)",
            zIndex: 1100,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <div
            style={{
              background: "var(--tc-bg)",
              border: "2px solid #d03020",
              borderRadius: "var(--tc-radius-md)",
              padding: "22px 26px",
              width: "560px",
              maxWidth: "95vw",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "12px" }}>
              <AlertTriangle size={20} color="#d03020" />
              <h3 style={{ margin: 0, fontSize: "14px", fontWeight: 800, color: "#d03020" }}>
                {fr ? "Action sensible : exclusion" : "Sensitive action: exclusion"}
              </h3>
            </div>

            <p style={{ fontSize: "12px", color: "var(--tc-text-sec)", lineHeight: 1.5, marginTop: 0 }}>
              {fr ? (
                <>
                  Vous allez exclure <strong>{asset.name}</strong> de la facturation ET de la surveillance ThreatClaw.
                  <br /><br />
                  Pendant l'exclusion, ThreatClaw n'enregistrera plus aucun nouveau finding, alert ou événement réseau ciblant cet asset. Vous ne recevrez aucune notification de compromission. <strong>Ne pas l'utiliser sur un asset critique en production.</strong>
                </>
              ) : (
                <>
                  You are about to exclude <strong>{asset.name}</strong> from BOTH billing AND ThreatClaw monitoring.
                  <br /><br />
                  While excluded, ThreatClaw will not record any new finding, alert, or network event targeting this asset. You will receive no compromise notification. <strong>Do not use on a critical production asset.</strong>
                </>
              )}
            </p>

            <div style={{ marginTop: "14px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text)" }}>
                {fr ? "Raison (audit) — obligatoire :" : "Reason (audit) — required:"}
              </label>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder={fr ? "ex: honeypot dédié, asset retiré, capteur bruyant…" : "e.g. dedicated honeypot, retired asset, noisy sensor…"}
                rows={2}
                style={{
                  width: "100%",
                  marginTop: "4px",
                  padding: "8px 10px",
                  fontSize: "12px",
                  fontFamily: "inherit",
                  background: "var(--tc-input)",
                  border: "1px solid var(--tc-border)",
                  borderRadius: "3px",
                  color: "var(--tc-text)",
                  resize: "vertical",
                }}
              />
            </div>

            <div style={{ marginTop: "12px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text)" }}>
                {fr ? "Auto-expiration (jours, 0 = jamais) :" : "Auto-expiry (days, 0 = never):"}
              </label>
              <input
                type="number"
                min={0}
                max={365}
                value={days}
                onChange={(e) => setDays(parseInt(e.target.value) || 0)}
                style={{
                  marginLeft: "8px",
                  padding: "5px 8px",
                  fontSize: "12px",
                  fontFamily: "monospace",
                  background: "var(--tc-input)",
                  border: "1px solid var(--tc-border)",
                  borderRadius: "3px",
                  color: "var(--tc-text)",
                  width: "80px",
                }}
              />
              <span style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginLeft: "8px" }}>
                {fr
                  ? "Recommandé : 90 jours. Au-delà, l'exclusion redevient active sans intervention."
                  : "Recommended: 90 days. After that, the asset returns to active monitoring without action."}
              </span>
            </div>

            <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end", marginTop: "20px" }}>
              <button
                onClick={() => setShowExcludeModal(false)}
                style={{
                  padding: "6px 14px",
                  fontSize: "11px",
                  fontWeight: 600,
                  fontFamily: "inherit",
                  border: "1px solid var(--tc-border)",
                  background: "var(--tc-input)",
                  color: "var(--tc-text)",
                  borderRadius: "3px",
                  cursor: "pointer",
                }}
              >
                {fr ? "Annuler" : "Cancel"}
              </button>
              <button
                onClick={() => submitExclusion(true)}
                disabled={!reason.trim() || busy === "exclude"}
                style={{
                  padding: "6px 14px",
                  fontSize: "11px",
                  fontWeight: 700,
                  fontFamily: "inherit",
                  border: "1px solid #d03020",
                  background: "#d03020",
                  color: "#fff",
                  borderRadius: "3px",
                  cursor: !reason.trim() ? "not-allowed" : "pointer",
                  opacity: !reason.trim() ? 0.5 : 1,
                }}
              >
                {busy === "exclude" ? "…" : fr ? "Confirmer l'exclusion" : "Confirm exclusion"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SecurityTab({ assetId }: { assetId: string }) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const locale = useLocale();

  useEffect(() => {
    setLoading(true);
    fetch(`/api/tc/assets/${assetId}/security`)
      .then(r => r.json())
      .then(d => setData(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [assetId]);

  if (loading) return <div style={{ textAlign: "center", padding: "20px", color: "var(--tc-text-muted)", fontSize: "10px" }}>Chargement...</div>;

  if (!data || !data.has_agent) return (
    <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-faint)", fontSize: "11px" }}>
      {locale === "fr"
        ? "Aucune donnée agent. Installez l'agent ThreatClaw sur cette machine pour alimenter cet onglet."
        : "No agent data. Install the ThreatClaw Agent on this machine to populate this tab."}
      <div style={{ marginTop: "12px" }}>
        <code style={{ fontSize: "10px", padding: "4px 8px", borderRadius: "4px", background: "var(--tc-input)", color: "var(--tc-blue)" }}>
          curl -fsSL get.threatclaw.io/agent | sudo bash
        </code>
      </div>
    </div>
  );

  const Section = ({ title, children, count }: { title: string; children: React.ReactNode; count?: number }) => (
    <div style={{ marginBottom: "14px" }}>
      <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-red)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "6px" }}>
        {title}{count !== undefined ? ` (${count})` : ""}
      </div>
      {children}
    </div>
  );

  const Badge = ({ text, color }: { text: string; color: string }) => (
    <span style={{ fontSize: "8px", padding: "1px 5px", borderRadius: "3px", background: `${color}15`, color, border: `1px solid ${color}30`, fontFamily: "monospace" }}>{text}</span>
  );

  return (
    <div style={{ maxHeight: "400px", overflowY: "auto" }}>
      {/* Users */}
      {data.users && Array.isArray(data.users) && data.users.length > 0 && (
        <Section title={locale === "fr" ? "Utilisateurs" : "Users"} count={data.users.length}>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {data.users.map((u: any, i: number) => (
              <Badge key={i} text={`${u.username || u.user || "?"}${u.uid === "0" || u.uid === 0 ? " (root)" : ""}`}
                color={u.uid === "0" || u.uid === 0 || u.is_admin ? "#d03020" : "var(--tc-blue)"} />
            ))}
          </div>
        </Section>
      )}

      {/* SSH Keys */}
      {data.ssh_keys && (
        <Section title={locale === "fr" ? "Clés SSH autorisées" : "Authorized SSH keys"}>
          <div style={{ fontSize: "10px", color: "var(--tc-text-sec)" }}>
            {typeof data.ssh_keys === "number" ? `${data.ssh_keys} clé(s)` :
             Array.isArray(data.ssh_keys) ? `${data.ssh_keys.length} clé(s)` :
             JSON.stringify(data.ssh_keys)}
          </div>
        </Section>
      )}

      {/* Listening ports */}
      {data.listening_ports && Array.isArray(data.listening_ports) && data.listening_ports.length > 0 && (
        <Section title={locale === "fr" ? "Ports en écoute" : "Listening ports"} count={data.listening_ports.length}>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {data.listening_ports.slice(0, 30).map((p: any, i: number) => {
              const port = p.port || 0;
              const suspicious = [4444, 5555, 1337, 31337].includes(Number(port));
              return <Badge key={i} text={`${port}/${p.protocol || "tcp"} ${p.name || ""}`} color={suspicious ? "#d03020" : "var(--tc-blue)"} />;
            })}
          </div>
        </Section>
      )}

      {/* Recent logins */}
      {data.logins && Array.isArray(data.logins) && data.logins.length > 0 && (
        <Section title={locale === "fr" ? "Connexions récentes" : "Recent logins"} count={data.logins.length}>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {data.logins.map((l: any, i: number) => (
              <Badge key={i} text={`${l.user || l.username || "?"} ${l.host ? `from ${l.host}` : ""}`} color="var(--tc-text-sec)" />
            ))}
          </div>
        </Section>
      )}

      {/* Docker containers */}
      {data.docker_containers && Array.isArray(data.docker_containers) && data.docker_containers.length > 0 && (
        <Section title="Docker" count={data.docker_containers.length}>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {data.docker_containers.map((c: any, i: number) => (
              <Badge key={i} text={`${c.name || c.id || "?"} (${c.status || c.state || "?"})`} color="#06b6d4" />
            ))}
          </div>
        </Section>
      )}

      {/* Shared folders */}
      {data.shared_folders && Array.isArray(data.shared_folders) && data.shared_folders.length > 0 && (
        <Section title={locale === "fr" ? "Partages réseau" : "Shared folders"} count={data.shared_folders.length}>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {data.shared_folders.map((s: any, i: number) => (
              <Badge key={i} text={s.name || s.path || "?"} color="var(--tc-amber)" />
            ))}
          </div>
        </Section>
      )}

      {/* Patches */}
      {data.patches && Array.isArray(data.patches) && data.patches.length > 0 && (
        <Section title={locale === "fr" ? "Mises à jour" : "Patches"} count={data.patches.length}>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)" }}>
            {data.patches.slice(0, 5).map((p: any, i: number) => (
              <div key={i}>{p.hotfix_id || p.title || p.name || JSON.stringify(p)}</div>
            ))}
            {data.patches.length > 5 && <div>... +{data.patches.length - 5}</div>}
          </div>
        </Section>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
// AssetScanSurface — banner inside the Réseau tab. Calls the
// /api/tc/scans/asset/{id} endpoint to display "Dernier scan: il y a
// X" + "Re-scanner" button. The button forces ttl_seconds=0 so the
// dedup window is bypassed.
// ─────────────────────────────────────────────────────────────────────
function AssetScanSurface({ asset }: { asset: any }) {
  const [scans, setScans] = useState<any[]>([]);
  const [running, setRunning] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const r = await fetch(`/api/tc/scans/asset/${encodeURIComponent(asset.id)}`);
      const d = await r.json();
      setScans(d.scans || []);
      setRunning(!!d.running);
    } catch {}
  }, [asset.id]);

  useEffect(() => { refresh(); }, [refresh]);
  // Auto-refresh while a scan is queued or running on this asset
  useEffect(() => {
    if (!running) return;
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, [running, refresh]);

  const ip = (asset.ip_addresses || []).find((s: string) => s && !s.includes(":")) || "";
  const lastNmap = scans.find((s) => s.scan_type === "nmap_fingerprint" && s.status === "done");
  const ago = lastNmap ? relTimeShort(lastNmap.finished_at) : null;

  const rescan = async () => {
    if (!ip) { setMsg("Pas d'IP sur cet asset"); return; }
    setBusy(true);
    setMsg(null);
    try {
      const r = await fetch("/api/tc/scans/queue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: ip,
          scan_type: "nmap_fingerprint",
          asset_id: asset.id,
          ttl_seconds: 0,
        }),
      });
      const d = await r.json();
      if (!r.ok || d.queued === false) {
        setMsg(d.error || d.reason || "Échec");
      } else {
        setMsg(`Scan #${d.scan_id} lancé`);
        setTimeout(refresh, 1000);
      }
    } catch (e: any) {
      setMsg(e.message || String(e));
    }
    setBusy(false);
  };

  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "space-between",
      gap: "12px", flexWrap: "wrap",
      padding: "10px 14px", marginBottom: "14px",
      background: running ? "rgba(48,128,208,0.06)" : "rgba(48,128,208,0.04)",
      border: `1px solid ${running ? "rgba(48,128,208,0.25)" : "var(--tc-border)"}`,
      borderRadius: "var(--tc-radius-sm)",
    }}>
      <div style={{ fontSize: "11px", color: "var(--tc-text-sec)" }}>
        {running ? (
          <>🔄 <strong>Scan Nmap en cours</strong> sur cet asset…</>
        ) : lastNmap ? (
          <>Dernier scan Nmap : <strong>{ago}</strong> · {(lastNmap.result_json?.open_ports_total ?? 0)} ports détectés</>
        ) : (
          <>Aucun scan Nmap pour le moment.</>
        )}
        {msg && <span style={{ marginLeft: "10px", color: "var(--tc-amber)", fontSize: "10px" }}>{msg}</span>}
      </div>
      <button
        onClick={rescan}
        disabled={busy || running || !ip}
        style={{
          padding: "5px 12px", fontSize: "10px", fontWeight: 600, fontFamily: "inherit",
          borderRadius: "var(--tc-radius-sm)", cursor: (busy || running || !ip) ? "default" : "pointer",
          background: "var(--tc-input)", color: "var(--tc-text-sec)",
          border: "1px solid var(--tc-border)",
          display: "inline-flex", alignItems: "center", gap: "4px",
          opacity: (!ip) ? 0.5 : 1,
        }}
      >
        <RefreshCw size={10} /> Re-scanner
      </button>
    </div>
  );
}

function relTimeShort(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "à l'instant";
  if (diff < 3_600_000) return `il y a ${Math.floor(diff / 60_000)} min`;
  if (diff < 86_400_000) return `il y a ${Math.floor(diff / 3_600_000)} h`;
  return new Date(iso).toLocaleDateString("fr-FR");
}

function AssetFindings({ asset }: { asset: any }) {
  const locale = useLocale();
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      // Search findings by asset name or IP
      const queries = [asset.name, ...(asset.ip_addresses || [])].filter(Boolean);
      const allFindings: any[] = [];
      const seen = new Set<number>();
      for (const q of queries) {
        const res = await fetch(`/api/tc/findings?limit=50`);
        if (res.ok) {
          const data = await res.json();
          for (const f of data.findings || []) {
            if (seen.has(f.id)) continue;
            // Match by asset field or by IP in metadata
            const matchAsset = f.asset && (f.asset === q || f.asset.includes(q));
            const matchIp = f.metadata?.agent_ip === q || f.metadata?.src_ip === q;
            if (matchAsset || matchIp) {
              seen.add(f.id);
              allFindings.push(f);
            }
          }
        }
      }
      setFindings(allFindings);
    } catch {}
    setLoading(false);
    setLoaded(true);
  };

  if (!loaded) {
    return (
      <div style={{ marginTop: "12px" }}>
        <button onClick={load} disabled={loading}
          style={{ fontSize: "10px", fontWeight: 700, padding: "6px 14px", borderRadius: "var(--tc-radius-sm)",
            background: "rgba(208,48,32,0.06)", border: "1px solid var(--tc-red-border)", color: "#d03020",
            cursor: "pointer", fontFamily: "inherit", display: "flex", alignItems: "center", gap: "6px" }}>
          <Shield size={12} /> {loading ? "Chargement..." : "Voir les vulnérabilités"}
        </button>
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div style={{ marginTop: "12px" }}>
        <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-red)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "6px" }}>{tr("vulnerabilities", locale)}</div>
        <div style={{ fontSize: "10px", color: "var(--tc-green)", display: "flex", alignItems: "center", gap: "4px" }}>
          <CheckCircle2 size={12} /> {locale === "fr" ? "Aucune vulnérabilité détectée sur cet asset" : "No vulnerabilities detected on this asset"}
        </div>
      </div>
    );
  }

  return (
    <div style={{ marginTop: "12px" }}>
      <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-red)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
        Vulnérabilités ({findings.length})
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "4px", maxHeight: "200px", overflowY: "auto" }}>
        {findings.map(f => (
          <a key={f.id} href={`/findings`}
            style={{ display: "flex", alignItems: "center", gap: "8px", padding: "6px 10px", borderRadius: "var(--tc-radius-sm)",
              background: "var(--tc-input)", border: "1px solid var(--tc-border)", textDecoration: "none", cursor: "pointer" }}>
            <span style={{ fontSize: "8px", fontWeight: 700, padding: "2px 6px", borderRadius: "3px",
              background: `${SEV_COLORS[f.severity] || "gray"}15`, color: SEV_COLORS[f.severity] || "gray",
              border: `1px solid ${SEV_COLORS[f.severity] || "gray"}30`, textTransform: "uppercase", flexShrink: 0 }}>
              {f.severity}
            </span>
            <span style={{ fontSize: "10px", color: "var(--tc-text)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {f.title}
            </span>
            <span style={{ fontSize: "9px", color: "var(--tc-text-muted)", flexShrink: 0 }}>{f.source || f.skill_id}</span>
          </a>
        ))}
      </div>
    </div>
  );
}

export default function AssetsPage() {
  const locale = useLocale();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("all");
  const [billableFilter, setBillableFilter] = useState<BillableFilter>("all");
  const [search, setSearch] = useState("");

  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [modalStep, setModalStep] = useState(0); // 0=pick category, 1=fill form
  const [editAsset, setEditAsset] = useState<Asset | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [assetTab, setAssetTab] = useState("summary");

  // Form state
  const [form, setForm] = useState({
    category: "", subcategory: "", name: "", role: "", criticality: "medium",
    ip: "", hostname: "", fqdn: "", os: "", url: "", mac: "",
    owner: "", location: "", notes: "",
  });

  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [aRes, cRes, countRes] = await Promise.all([
        fetch(`/api/tc/assets?limit=500${activeTab !== "all" ? `&category=${activeTab}` : ""}`, { signal: AbortSignal.timeout(10000) }),
        fetch("/api/tc/assets/categories", { signal: AbortSignal.timeout(10000) }),
        fetch("/api/tc/assets/counts", { signal: AbortSignal.timeout(10000) }),
      ]);
      const aData = await aRes.json();
      const cData = await cRes.json();
      const countData = await countRes.json();
      setAssets(aData.assets || []);
      setCategories(cData.categories || []);
      const m: Record<string, number> = {};
      for (const c of countData.counts || []) m[c.category] = c.count;
      setCounts(m);
      setError(null);
    } catch {
      setError("Backend non accessible — verifiez que le service tourne");
    }
    setLoading(false);
  }, [activeTab]);

  useEffect(() => { loadData(); }, [loadData]);

  // ── Modal handlers ──

  const openAdd = () => {
    setEditAsset(null);
    setForm({ category: "", subcategory: "", name: "", role: "", criticality: "medium", ip: "", hostname: "", fqdn: "", os: "", url: "", mac: "", owner: "", location: "", notes: "" });
    setModalStep(0);
    setShowModal(true);
  };

  const openEdit = (a: Asset) => {
    setEditAsset(a);
    setForm({
      category: a.category, subcategory: a.subcategory || "", name: a.name,
      role: a.role || "", criticality: a.criticality,
      ip: a.ip_addresses.join(", "), hostname: a.hostname || "",
      fqdn: a.fqdn || "", os: a.os || "", url: a.url || "",
      mac: a.mac_address || "", owner: a.owner || "",
      location: a.location || "", notes: a.notes || "",
    });
    setModalStep(1);
    setShowModal(true);
  };

  const selectCategory = (catId: string) => {
    setForm(f => ({ ...f, category: catId }));
    setModalStep(1);
  };

  const handleSave = async () => {
    const body: Record<string, unknown> = {
      name: form.name, category: form.category,
      subcategory: form.subcategory || undefined,
      role: form.role || undefined, criticality: form.criticality,
      hostname: form.hostname || undefined, fqdn: form.fqdn || undefined,
      os: form.os || undefined, url: form.url || undefined,
      mac_address: form.mac || undefined,
      owner: form.owner || undefined, location: form.location || undefined,
      notes: form.notes || undefined,
    };
    if (form.ip) body.ip_addresses = form.ip.split(",").map(s => s.trim()).filter(Boolean);
    if (editAsset) body.id = editAsset.id;
    await fetch("/api/tc/assets", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    setShowModal(false);
    loadData();
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Supprimer cet asset ?")) return;
    await fetch(`/api/tc/assets/${id}`, { method: "DELETE" });
    loadData();
  };

  // ── Filtered assets ──
  // Two filter dimensions:
  //   - activeTab: by category (server / workstation / etc.) — drives
  //     the API `?category=` so the result is server-side narrowed.
  //   - billableFilter: by billable bucket (V67) — applied client-side
  //     because the bucket is computed from inventory_status +
  //     distinct_days_seen_30d and the API doesn't pivot on those yet.
  //   - search: free-text filter on name/IP/hostname/role/os.

  const billablePred =
    BILLABLE_FILTERS.find((f) => f.id === billableFilter)?.predicate ?? (() => true);

  // Per-bucket counts so the filter row shows e.g. "Billable (12)".
  const billableCounts: Record<BillableFilter, number> = BILLABLE_FILTERS.reduce(
    (acc, f) => {
      acc[f.id] = assets.filter(f.predicate).length;
      return acc;
    },
    {} as Record<BillableFilter, number>,
  );

  const filtered = assets.filter((a) => {
    if (!billablePred(a)) return false;
    if (!search) return true;
    const s = search.toLowerCase();
    return a.name.toLowerCase().includes(s) || a.ip_addresses.some(ip => ip.includes(s)) ||
      (a.hostname || "").toLowerCase().includes(s) || (a.role || "").toLowerCase().includes(s) ||
      (a.os || "").toLowerCase().includes(s);
  });

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const activeCat = categories.find(c => c.id === form.category);

  // CSV import handler lifted out of the JSX so it's reusable across the
  // hidden input and the PageShell right-action buttons. Keeps behaviour
  // identical to the pre-PageShell version of the page.
  const handleCsvImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const lines = text.split("\n").filter(l => l.trim());
    if (lines.length < 2) return;
    const headers = lines[0].split(",").map(h => h.trim().toLowerCase());
    let imported = 0;
    for (let i = 1; i < lines.length; i++) {
      const vals = lines[i].split(",").map(v => v.trim().replace(/^"|"$/g, ""));
      const row: Record<string, string> = {};
      headers.forEach((h, j) => { row[h] = vals[j] || ""; });
      try {
        await fetch("/api/tc/assets", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: row.name || row.hostname || row.ip || `Asset-${i}`,
            category: row.category || "unknown",
            criticality: row.criticality || "medium",
            ip_addresses: row.ip ? [row.ip] : [],
            hostname: row.hostname || null,
            os: row.os || null,
            role: row.role || null,
          }),
        });
        imported++;
      } catch { /* swallow — best-effort import */ }
    }
    alert(`${imported} asset(s) importé(s)`);
    loadData();
    e.target.value = "";
  };

  const handleCsvExport = () => {
    const csv = ["name,category,criticality,ip,hostname,os,role",
      ...assets.map(a => `"${a.name}","${a.category}","${a.criticality}","${a.ip_addresses?.join(";") || ""}","${a.hostname || ""}","${a.os || ""}","${a.role || ""}"`)
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "threatclaw-assets.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const headerActions = (
    <div style={{ display: "flex", gap: "8px" }}>
      <button onClick={openAdd} style={btnPrimary}><Plus size={13} /> {locale === "fr" ? "Ajouter" : "Add"}</button>
      <button onClick={() => document.getElementById("csv-import")?.click()} style={btnSecondary} title={locale === "fr" ? "Importer CSV" : "Import CSV"}>
        <Upload size={12} />
      </button>
      <input id="csv-import" type="file" accept=".csv" style={{ display: "none" }} onChange={handleCsvImport} />
      <button onClick={handleCsvExport} style={btnSecondary} title={locale === "fr" ? "Exporter CSV" : "Export CSV"}>
        <Download size={12} />
      </button>
      <button onClick={loadData} style={btnSecondary} title={locale === "fr" ? "Rafraîchir" : "Refresh"}>
        <RefreshCw size={12} />
      </button>
    </div>
  );

  return (
    <PageShell
      title={tr("assets", locale)}
      subtitle={`${total} asset${total !== 1 ? "s" : ""} ${locale === "fr" ? "dans votre infrastructure" : "in your infrastructure"}`}
      right={headerActions}
    >
      {error && <ErrorBanner message={error} onRetry={loadData} />}

      {/* Category tabs */}
      <div style={{ display: "flex", gap: "4px", marginBottom: "16px", flexWrap: "wrap" }}>
        <button onClick={() => setActiveTab("all")} style={{
          padding: "6px 12px", fontSize: "10px", fontWeight: 700, borderRadius: "var(--tc-radius-sm)",
          cursor: "pointer", fontFamily: "inherit", textTransform: "uppercase", letterSpacing: "0.05em",
          background: activeTab === "all" ? "var(--tc-red)" : "var(--tc-input)",
          color: activeTab === "all" ? "#fff" : "var(--tc-text-muted)",
          border: activeTab === "all" ? "none" : "1px solid var(--tc-border)",
        }}>
          Tous ({total})
        </button>
        {categories.filter(c => (counts[c.id] || 0) > 0 || c.id === "unknown").map(cat => {
          const Icon = ICON_MAP[cat.icon] || HelpCircle;
          const count = counts[cat.id] || 0;
          return (
            <button key={cat.id} onClick={() => setActiveTab(cat.id)} style={{
              padding: "6px 12px", fontSize: "10px", fontWeight: 600, borderRadius: "var(--tc-radius-sm)",
              cursor: "pointer", fontFamily: "inherit", display: "flex", alignItems: "center", gap: "4px",
              background: activeTab === cat.id ? cat.color : "var(--tc-input)",
              color: activeTab === cat.id ? "#fff" : "var(--tc-text-muted)",
              border: activeTab === cat.id ? "none" : "1px solid var(--tc-border)",
            }}>
              <Icon size={11} /> {locale === "en" ? (cat.label_en || cat.label) : cat.label} ({count})
            </button>
          );
        })}
      </div>

      {/* Billable filter row (V67) */}
      <div
        style={{
          display: "flex",
          gap: "4px",
          marginBottom: "16px",
          flexWrap: "wrap",
          alignItems: "center",
          paddingBottom: "10px",
          borderBottom: "1px solid var(--tc-border)",
        }}
      >
        <span
          style={{
            fontSize: "9px",
            color: "var(--tc-text-muted)",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            marginRight: "8px",
          }}
        >
          {locale === "fr" ? "Statut facturation" : "Billing status"}
        </span>
        {BILLABLE_FILTERS.map((f) => {
          const n = billableCounts[f.id] ?? 0;
          const active = billableFilter === f.id;
          return (
            <button
              key={f.id}
              onClick={() => setBillableFilter(f.id)}
              style={{
                padding: "5px 10px",
                fontSize: "10px",
                fontWeight: 600,
                fontFamily: "inherit",
                borderRadius: "var(--tc-radius-sm)",
                cursor: "pointer",
                background: active ? "var(--tc-blue)" : "var(--tc-input)",
                color: active ? "#fff" : "var(--tc-text-muted)",
                border: active ? "none" : "1px solid var(--tc-border)",
              }}
            >
              {locale === "fr" ? f.labelFr : f.labelEn} ({n})
            </button>
          );
        })}
      </div>

      {/* Search */}
      <div style={{ marginBottom: "16px", position: "relative" }}>
        <Search size={13} style={{ position: "absolute", left: "10px", top: "9px", color: "var(--tc-text-muted)" }} />
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder={tr("searchAssets", locale)}
          style={{ ...inputStyle, paddingLeft: "30px" }} />
      </div>

      {/* Assets list */}
      {loading ? (
        <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-muted)" }}>
          <Loader2 size={20} className="animate-spin" style={{ margin: "0 auto 8px" }} /> Chargement...
        </div>
      ) : filtered.length === 0 ? (
        <NeuCard style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-muted)", fontSize: "12px" }}>
          {search ? tr("noAssetFilter", locale) : tr("noAssets", locale)}
        </NeuCard>
      ) : (
        <div>
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {filtered.map(a => {
            const cat = categories.find(c => c.id === a.category);
            const Icon = ICON_MAP[cat?.icon || "help-circle"] || HelpCircle;
            const crit = CRIT_COLORS[a.criticality] || { color: "var(--tc-text-muted)", label: a.criticality };
            return (
              <div key={a.id}>
                <NeuCard style={{ padding: "12px 14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  {/* Icon */}
                  <div style={{ width: "32px", height: "32px", borderRadius: "var(--tc-radius-sm)", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: cat?.color || "var(--tc-text-muted)", flexShrink: 0 }}>
                    <Icon size={16} />
                  </div>

                  {/* Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                      <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)" }}>{a.name}</span>
                      <span style={{ fontSize: "8px", fontWeight: 700, padding: "1px 5px", borderRadius: "3px", textTransform: "uppercase",
                        background: `${crit.color}15`, color: crit.color, border: `1px solid ${crit.color}30` }}>
                        {crit.label}
                      </span>
                      {a.subcategory && <span style={{ fontSize: "8px", color: "var(--tc-text-muted)", padding: "1px 4px", borderRadius: "3px", background: "var(--tc-input)" }}>{a.subcategory}</span>}
                      {a.source !== "manual" && <span style={{ fontSize: "8px", color: "var(--tc-blue)", padding: "1px 4px", borderRadius: "3px", background: "rgba(48,128,208,0.08)" }}>{a.source}</span>}
                      {a.category === "unknown" && <span style={{ fontSize: "8px", color: "var(--tc-amber)", padding: "1px 4px", borderRadius: "3px", background: "rgba(208,144,32,0.08)" }}>auto-détecté</span>}
                      {/* V67 — inventory_status badge. The transient
                          bucket also surfaces the days-seen progress
                          so the operator can guess when it'll flip
                          to billable. */}
                      {a.inventory_status && INVENTORY_BADGE[a.inventory_status] && (() => {
                        const badge = INVENTORY_BADGE[a.inventory_status]!;
                        const lbl = locale === "fr" ? badge.labelFr : badge.labelEn;
                        const isTransient = a.inventory_status === "observed_transient";
                        const days = a.distinct_days_seen_30d ?? 0;
                        const tail = isTransient ? ` · ${days}/3 j` : "";
                        return (
                          <span style={{
                            fontSize: "8px", fontWeight: 700, padding: "1px 5px",
                            borderRadius: "3px", textTransform: "uppercase",
                            background: `${badge.color}15`, color: badge.color,
                            border: `1px solid ${badge.color}30`,
                          }}>{lbl}{tail}</span>
                        );
                      })()}
                    </div>
                    <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "2px", display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
                      {a.ip_addresses.length > 0 && <span style={{ fontFamily: "monospace" }}>{a.ip_addresses.join(", ")}</span>}
                      {a.hostname && <span>{a.hostname}</span>}
                      {a.os && <span>{a.os}</span>}
                      {a.role && <span style={{ fontStyle: "italic" }}>{a.role}</span>}
                      {a.services && Array.isArray(a.services) && a.services.length > 0 && (
                        <span style={{ fontSize: "9px", color: "var(--tc-text-faint)" }}>
                          {a.services.filter((s: any) => s.service).map((s: any) => s.service).slice(0, 5).join(", ")}
                          {a.services.length > 5 && ` +${a.services.length - 5}`}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div style={{ display: "flex", gap: "4px", flexShrink: 0 }} onClick={e => e.stopPropagation()}>
                    <button onClick={() => { setAssetTab("summary"); setExpandedId(a.id); }} style={{ background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", cursor: "pointer", color: "var(--tc-text-sec)", padding: "4px 8px", fontSize: "9px", fontWeight: 600, fontFamily: "inherit", display: "flex", alignItems: "center", gap: "3px" }}><Eye size={11} /> Détails</button>
                    <button onClick={() => openEdit(a)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: "4px" }}><Settings size={13} /></button>
                    <button onClick={() => handleDelete(a.id)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: "4px" }}><Trash2 size={13} /></button>
                  </div>

                </div>
                </NeuCard>

              </div>
            );
          })}
        </div>

        {/* Asset Detail Modal */}
        {expandedId && (() => {
          const a = assets.find(x => x.id === expandedId);
          if (!a) return null;
          const cat = categories.find(c => c.id === a.category);
          const crit = CRIT_COLORS[a.criticality] || { color: "var(--tc-text-muted)", label: a.criticality };
          const Icon = ICON_MAP[cat?.icon || "help-circle"] || HelpCircle;
          return (
            <div onClick={e => { if (e.target === e.currentTarget) setExpandedId(null); }}
              style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div style={{
              background: "var(--tc-bg)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)",
              padding: "24px", width: "700px", maxWidth: "95vw", maxHeight: "90vh", overflowY: "auto",
            }}>
              {/* Header */}
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <div style={{ width: "40px", height: "40px", borderRadius: "var(--tc-radius-sm)", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: cat?.color || "var(--tc-text-muted)" }}>
                    <Icon size={20} />
                  </div>
                  <div>
                    <div style={{ fontSize: "16px", fontWeight: 800, color: "var(--tc-text)" }}>{a.name}</div>
                    <div style={{ display: "flex", gap: "6px", marginTop: "2px" }}>
                      <span style={{ fontSize: "9px", fontWeight: 700, padding: "1px 6px", borderRadius: "3px", background: `${crit.color}15`, color: crit.color, border: `1px solid ${crit.color}30`, textTransform: "uppercase" }}>{crit.label}</span>
                      <span style={{ fontSize: "9px", padding: "1px 6px", borderRadius: "3px", background: "var(--tc-input)", color: "var(--tc-text-muted)" }}>{cat?.label || a.category}</span>
                      {(a as any).sources?.length > 0 && <span style={{ fontSize: "8px", padding: "1px 6px", borderRadius: "3px", background: "rgba(48,128,208,0.08)", color: "var(--tc-blue)" }}>Sources: {(a as any).sources.join(", ")}</span>}
                    </div>
                  </div>
                </div>
                <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                  <button onClick={() => openEdit(a)} style={{ padding: "6px 10px", fontSize: "10px", fontWeight: 600, fontFamily: "inherit", borderRadius: "var(--tc-radius-sm)", background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text-sec)", cursor: "pointer" }}>Modifier</button>
                  <button onClick={() => setExpandedId(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: "4px" }}><X size={16} /></button>
                </div>
              </div>

              {/* Tabs */}
              {(() => {
                const software = (a as any).software || [];
                const hasSoftware = Array.isArray(software) && software.length > 0;
                const hasServices = a.services && Array.isArray(a.services) && a.services.length > 0;
                const tabs = [
                  { id: "summary", label: "Résumé" },
                  { id: "software", label: `Logiciels${hasSoftware ? ` (${software.length})` : ""}` },
                  { id: "network", label: "Réseau" },
                  { id: "security", label: "Sécurité" },
                  { id: "findings", label: "Findings" },
                ];
                const activeTab = assetTab;
                const setActiveTab = setAssetTab;
                return (
                  <>
                    <div style={{ display: "flex", gap: "2px", marginBottom: "16px", borderBottom: "1px solid var(--tc-border)", paddingBottom: "0" }}>
                      {tabs.map(tab => (
                        <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
                          padding: "8px 14px", fontSize: "10px", fontWeight: 700, fontFamily: "inherit",
                          background: "transparent", border: "none", borderBottom: activeTab === tab.id ? "2px solid var(--tc-red)" : "2px solid transparent",
                          color: activeTab === tab.id ? "var(--tc-text)" : "var(--tc-text-muted)",
                          cursor: "pointer", transition: "all 150ms",
                        }}>{tab.label}</button>
                      ))}
                    </div>

                    {/* ── Tab: Résumé ── */}
                    {activeTab === "summary" && (
                      <div>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "10px", marginBottom: "16px" }}>
                          <div><span style={labelStyle}>IP</span><div style={{ color: "var(--tc-text)", fontFamily: "monospace" }}>{a.ip_addresses.join(", ") || "—"}</div></div>
                          <div><span style={labelStyle}>MAC</span><div style={{ color: "var(--tc-text)", fontFamily: "monospace" }}>{a.mac_address || "—"} {a.mac_vendor && <span style={{ color: "var(--tc-text-muted)" }}>({a.mac_vendor})</span>}</div></div>
                          <div><span style={labelStyle}>Hostname</span><div style={{ color: "var(--tc-text)" }}>{a.hostname || "—"}{a.fqdn ? ` (${a.fqdn})` : ""}</div></div>
                          <div><span style={labelStyle}>OS</span><div style={{ color: "var(--tc-text)" }}>{a.os || "—"}</div></div>
                          <div><span style={labelStyle}>Rôle</span><div style={{ color: "var(--tc-text)" }}>{a.role || "—"}</div></div>
                          <div><span style={labelStyle}>Responsable</span><div style={{ color: "var(--tc-text)" }}>{a.owner || "—"}</div></div>
                          <div>
                            <span style={labelStyle}>Criticité</span>
                            <select
                              value={a.criticality}
                              onChange={async (e) => {
                                const next = e.target.value;
                                const prev = a.criticality;
                                // Optimistic update so the badge in the header
                                // reflects the new value immediately.
                                setAssets(rows => rows.map(r => r.id === a.id ? { ...r, criticality: next } : r));
                                try {
                                  const res = await fetch(`/api/tc/assets/${a.id}/criticality`, {
                                    method: "PUT",
                                    headers: { "Content-Type": "application/json" },
                                    body: JSON.stringify({ criticality: next }),
                                  });
                                  const j = await res.json().catch(() => ({}));
                                  if (j?.error) {
                                    setAssets(rows => rows.map(r => r.id === a.id ? { ...r, criticality: prev } : r));
                                    alert("Criticité non sauvegardée : " + j.error);
                                  }
                                } catch (err) {
                                  setAssets(rows => rows.map(r => r.id === a.id ? { ...r, criticality: prev } : r));
                                  alert("Criticité non sauvegardée (réseau)");
                                }
                              }}
                              style={{
                                width: "100%", padding: "4px 6px", fontSize: "10px", fontFamily: "inherit",
                                background: "var(--tc-input)", border: "1px solid var(--tc-border)",
                                borderRadius: "var(--tc-radius-sm)", color: "var(--tc-text)", cursor: "pointer",
                              }}
                            >
                              <option value="low">Bas</option>
                              <option value="medium">Moyen</option>
                              <option value="high">Haut</option>
                              <option value="critical">Critique</option>
                              <option value="unknown">Inconnu</option>
                            </select>
                          </div>
                          {a.url && <div style={{ gridColumn: "1/3" }}><span style={labelStyle}>URL</span><div style={{ color: "var(--tc-blue)", fontFamily: "monospace", fontSize: "9px" }}>{a.url}</div></div>}
                        </div>
                        <GraphIntelSection assetId={a.id} />
                        {a.tags && a.tags.length > 0 && (
                          <div style={{ marginTop: "12px" }}>
                            <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-red)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "6px" }}>Tags</div>
                            <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                              {a.tags.map((t: string, i: number) => <span key={i} style={{ fontSize: "8px", padding: "1px 5px", borderRadius: "3px", background: "rgba(48,128,208,0.08)", color: "var(--tc-blue)", border: "1px solid rgba(48,128,208,0.15)" }}>{t}</span>)}
                            </div>
                          </div>
                        )}
                        {a.notes && (
                          <div style={{ marginTop: "10px" }}>
                            <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-red)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>Notes</div>
                            <div style={{ fontSize: "10px", color: "var(--tc-text-sec)", fontStyle: "italic" }}>{a.notes}</div>
                          </div>
                        )}
                        <div style={{ marginTop: "14px", paddingTop: "10px", borderTop: "1px solid var(--tc-border)", display: "flex", gap: "12px", flexWrap: "wrap", fontSize: "9px", color: "var(--tc-text-muted)" }}>
                          <span>Source: {a.source}</span>
                          <span>Première vue: {new Date(a.first_seen).toLocaleDateString("fr-FR")}</span>
                          <span>Dernière vue: {new Date(a.last_seen).toLocaleDateString("fr-FR")}</span>
                        </div>
                      </div>
                    )}

                    {/* ── Tab: Logiciels ── */}
                    {activeTab === "software" && (
                      <div>
                        {hasSoftware ? (
                          <div style={{ maxHeight: "400px", overflowY: "auto" }}>
                            <table style={{ width: "100%", fontSize: "10px", borderCollapse: "collapse" }}>
                              <thead>
                                <tr style={{ borderBottom: "1px solid var(--tc-border)", textAlign: "left" }}>
                                  <th style={{ padding: "6px 8px", fontWeight: 700, color: "var(--tc-text-muted)" }}>Nom</th>
                                  <th style={{ padding: "6px 8px", fontWeight: 700, color: "var(--tc-text-muted)" }}>Version</th>
                                  <th style={{ padding: "6px 8px", fontWeight: 700, color: "var(--tc-text-muted)" }}>Source</th>
                                </tr>
                              </thead>
                              <tbody>
                                {software.map((s: any, i: number) => (
                                  <tr key={i} style={{ borderBottom: "1px solid var(--tc-border)" }}>
                                    <td style={{ padding: "5px 8px", color: "var(--tc-text)", fontWeight: 600 }}>{s.name}</td>
                                    <td style={{ padding: "5px 8px", fontFamily: "monospace", color: "var(--tc-text-sec)" }}>{s.version || "—"}</td>
                                    <td style={{ padding: "5px 8px", color: "var(--tc-text-muted)" }}>{s.source || "—"}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-faint)", fontSize: "11px" }}>
                            Aucun logiciel détecté. Installez l&apos;agent ThreatClaw sur cette machine pour obtenir l&apos;inventaire logiciel.
                          </div>
                        )}
                      </div>
                    )}

                    {/* ── Tab: Réseau ── */}
                    {activeTab === "network" && (
                      <div>
                        <AssetScanSurface asset={a} />
                        {hasServices ? (
                          <>
                            <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-red)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>Services / Ports ({a.services.length})</div>
                            <div style={{ display: "flex", gap: "4px", flexWrap: "wrap", marginBottom: "16px" }}>
                              {a.services.map((s: any, i: number) => (
                                <span key={i} style={{ fontSize: "9px", padding: "3px 8px", borderRadius: "4px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", fontFamily: "monospace", display: "inline-flex", alignItems: "center", gap: "4px" }}>
                                  <span style={{ fontWeight: 700, color: "var(--tc-blue)" }}>{s.port}</span>
                                  <span style={{ color: "var(--tc-text-muted)" }}>/</span>
                                  <span>{s.proto || "tcp"}</span>
                                  {s.service && <span style={{ color: "var(--tc-text-sec)" }}>{s.service}</span>}
                                  {s.product && <span style={{ color: "var(--tc-amber)", fontWeight: 600 }}>{s.product}</span>}
                                  {s.version && <span style={{ color: "var(--tc-text-muted)", fontSize: "8px" }}>v{s.version}</span>}
                                </span>
                              ))}
                            </div>
                          </>
                        ) : (
                          <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-faint)", fontSize: "11px" }}>
                            Aucun service réseau détecté. Le scan Nmap se déclenche automatiquement à la première observation de l&apos;asset (TTL 1h). Sinon, utilisez le bouton « Re-scanner » ci-dessus.
                          </div>
                        )}
                      </div>
                    )}

                    {/* ── Tab: Sécurité ── */}
                    {activeTab === "security" && (
                      <SecurityTab assetId={a.id} />
                    )}

                    {/* ── Tab: Findings ── */}
                    {activeTab === "findings" && (
                      <AssetFindings asset={a} />
                    )}
                  </>
                );
              })()}

              {/* V68 — Exclusion + Merge actions (always shown, ops surface) */}
              <ExclusionPanel asset={a} onChanged={loadData} />

              {/* Delete button (bottom) */}
              <div style={{ marginTop: "14px", textAlign: "right" }}>
                <button onClick={() => handleDelete(a.id)} style={{ padding: "6px 12px", fontSize: "10px", fontWeight: 600, fontFamily: "inherit", borderRadius: "var(--tc-radius-sm)", background: "rgba(208,48,32,0.06)", border: "1px solid var(--tc-red-border)", color: "#d03020", cursor: "pointer" }}>
                  <Trash2 size={10} /> Supprimer
                </button>
              </div>
            </div>
            </div>
          );
        })()}
        </div>
      )}

      {/* ═══ Add/Edit Modal ═══ */}
      {showModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}
          onClick={e => { if (e.target === e.currentTarget) setShowModal(false); }}>
          <div style={{ background: "var(--tc-bg)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)", padding: "24px", width: "520px", maxHeight: "85vh", overflowY: "auto" }}>

            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h2 style={{ fontSize: "16px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>
                {editAsset ? "Modifier l'asset" : modalStep === 0 ? "Quel type d'asset ?" : `Nouvel asset — ${activeCat?.label || ""}`}
              </h2>
              <button onClick={() => setShowModal(false)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)" }}><X size={16} /></button>
            </div>

            {/* Step 0: Category picker */}
            {modalStep === 0 && !editAsset && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                {categories.filter(c => c.id !== "unknown").map(cat => {
                  const Icon = ICON_MAP[cat.icon] || HelpCircle;
                  return (
                    <button key={cat.id} onClick={() => selectCategory(cat.id)} style={{
                      ...cardStyle, padding: "14px", cursor: "pointer", textAlign: "left" as const,
                      border: "1px solid var(--tc-border)", display: "flex", flexDirection: "column" as const, gap: "6px",
                      transition: "border-color 0.2s",
                    }}
                    onMouseEnter={e => (e.currentTarget.style.borderColor = cat.color)}
                    onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--tc-border)")}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <Icon size={18} color={cat.color} />
                        <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)" }}>
                          {locale === "en" ? (cat.label_en || cat.label) : cat.label}
                        </span>
                      </div>
                      <span style={{ fontSize: "9px", color: "var(--tc-text-muted)", lineHeight: "1.4" }}>
                        {CAT_DESCRIPTIONS[cat.id] || `Sous-types : ${cat.subcategories.join(", ")}`}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}

            {/* Step 1: Form adapted to category */}
            {(modalStep === 1 || editAsset) && (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>

                {/* Services detected (read-only, shown on edit) */}
                {editAsset && editAsset.services && Array.isArray(editAsset.services) && editAsset.services.length > 0 && (
                  <div style={{ padding: "10px 12px", borderRadius: "var(--tc-radius-sm)", background: "var(--tc-input)", border: "1px solid var(--tc-border)" }}>
                    <div style={{ fontSize: "9px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "6px" }}>Services détectés par scan</div>
                    <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                      {editAsset.services.map((s: any, i: number) => (
                        <span key={i} style={{ fontSize: "9px", padding: "3px 8px", borderRadius: "4px", background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)", fontFamily: "monospace", display: "inline-flex", alignItems: "center", gap: "4px" }}>
                          <span style={{ fontWeight: 700, color: "var(--tc-blue)" }}>{s.port}</span>
                          <span style={{ color: "var(--tc-text-muted)" }}>/</span>
                          <span>{s.proto || "tcp"}</span>
                          {s.service && <span style={{ color: "var(--tc-text-sec)" }}>{s.service}</span>}
                          {s.product && <span style={{ color: "var(--tc-amber)", fontWeight: 600 }}>{s.product}</span>}
                          {s.version && <span style={{ color: "var(--tc-text-muted)", fontSize: "8px" }}>v{s.version}</span>}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Name */}
                <div>
                  <label style={labelStyle}>Nom de l{"'"}asset *</label>
                  <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder={form.category === "website" ? "monsite.fr" : form.category === "server" ? "srv-web-01" : form.category === "workstation" ? "PC-COMPTA-01" : "Nom..."}
                    style={inputStyle} />
                </div>

                {/* Category + Criticality */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                  <div>
                    <label style={labelStyle}>Catégorie</label>
                    <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value, subcategory: "" }))} style={inputStyle}>
                      {categories.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
                    </select>
                  </div>
                  <div>
                    <label style={labelStyle}>Criticité</label>
                    <select value={form.criticality} onChange={e => setForm(f => ({ ...f, criticality: e.target.value }))} style={inputStyle}>
                      <option value="critical">Critique — essentiel au fonctionnement</option>
                      <option value="high">Haut — impact fort si compromis</option>
                      <option value="medium">Moyen — impact modéré</option>
                      <option value="low">Bas — impact limité</option>
                    </select>
                  </div>
                </div>

                {/* Subcategory (dynamic from selected category) */}
                {activeCat && activeCat.subcategories.length > 0 && (
                  <div>
                    <label style={labelStyle}>Sous-type / Rôle technique</label>
                    <select value={form.subcategory} onChange={e => setForm(f => ({ ...f, subcategory: e.target.value }))} style={inputStyle}>
                      <option value="">— Choisir —</option>
                      {activeCat.subcategories.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                )}

                {/* Role description */}
                <div>
                  <label style={labelStyle}>Description du rôle</label>
                  <input value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
                    placeholder={form.category === "server" ? "Ex: Serveur de base de données PostgreSQL production" : form.category === "website" ? "Ex: Site vitrine WordPress avec WooCommerce" : "Que fait cet asset dans votre infrastructure ?"}
                    style={inputStyle} />
                </div>

                {/* URL (websites only) */}
                {(form.category === "website" || form.url) && (
                  <div>
                    <label style={labelStyle}>URL</label>
                    <input value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
                      placeholder="https://monsite.fr" style={inputStyle} />
                  </div>
                )}

                {/* IP + Hostname (not for websites unless on-premise) */}
                {form.category !== "website" && (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                      <div>
                        <label style={labelStyle}>Adresse(s) IP</label>
                        <input value={form.ip} onChange={e => setForm(f => ({ ...f, ip: e.target.value }))}
                          placeholder="192.168.1.10 (ou plusieurs séparées par ,)" style={inputStyle} />
                      </div>
                      <div>
                        <label style={labelStyle}>Hostname</label>
                        <input value={form.hostname} onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))}
                          placeholder={form.category === "workstation" ? "PC-COMPTA-01" : "srv-web-01"} style={inputStyle} />
                      </div>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                      <div>
                        <label style={labelStyle}>Adresse MAC</label>
                        <input value={form.mac} onChange={e => setForm(f => ({ ...f, mac: e.target.value }))}
                          placeholder="00:1A:2B:3C:4D:5E (optionnel)" style={inputStyle} />
                      </div>
                      <div>
                        <label style={labelStyle}>Système d{"'"}exploitation</label>
                        <input value={form.os} onChange={e => setForm(f => ({ ...f, os: e.target.value }))}
                          placeholder={form.category === "network" ? "FortiOS 7.4" : form.category === "ot" ? "Firmware v2.1" : "Ubuntu 22.04 / Windows Server 2022"} style={inputStyle} />
                      </div>
                    </div>
                  </>
                )}

                {/* Website: special fields */}
                {form.category === "website" && (
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                    <div>
                      <label style={labelStyle}>Adresse IP (si on-premise)</label>
                      <input value={form.ip} onChange={e => setForm(f => ({ ...f, ip: e.target.value }))} placeholder="Optionnel" style={inputStyle} />
                    </div>
                    <div>
                      <label style={labelStyle}>Hostname serveur</label>
                      <input value={form.hostname} onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))} placeholder="Optionnel" style={inputStyle} />
                    </div>
                  </div>
                )}

                {/* Owner + Location */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                  <div>
                    <label style={labelStyle}>Responsable</label>
                    <input value={form.owner} onChange={e => setForm(f => ({ ...f, owner: e.target.value }))} placeholder="Jean Dupont / Équipe Infra" style={inputStyle} />
                  </div>
                  <div>
                    <label style={labelStyle}>Localisation</label>
                    <input value={form.location} onChange={e => setForm(f => ({ ...f, location: e.target.value }))} placeholder="Bureau Paris / Datacenter OVH" style={inputStyle} />
                  </div>
                </div>

                {/* Notes */}
                <div>
                  <label style={labelStyle}>Notes</label>
                  <textarea value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
                    placeholder="Informations complémentaires pour le RSSI..."
                    style={{ ...inputStyle, minHeight: "50px", resize: "vertical" }} />
                </div>

                {/* Buttons */}
                <div style={{ display: "flex", justifyContent: "space-between", marginTop: "8px" }}>
                  {!editAsset && (
                    <button onClick={() => setModalStep(0)} style={btnSecondary}>
                      <ChevronLeft size={12} /> Changer de catégorie
                    </button>
                  )}
                  <button onClick={handleSave} disabled={!form.name} style={{
                    ...btnPrimary, marginLeft: "auto",
                    opacity: form.name ? 1 : 0.5, cursor: form.name ? "pointer" : "default",
                  }}>
                    <CheckCircle2 size={13} /> {editAsset ? tr("update", locale) : tr("add", locale)}
                  </button>
                </div>

                {/* Hint */}
                <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", fontStyle: "italic", marginTop: "4px" }}>
                  ThreatClaw enrichira automatiquement cet asset (ports, services, OS) lors du prochain scan réseau.
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </PageShell>
  );
}

// ── Graph Intelligence Section (loaded on expand) ──

function GraphIntelSection({ assetId }: { assetId: string }) {
  const [data, setData] = useState<{ attackers?: any[]; cves?: any[]; blast?: any; confidence?: number; loading: boolean }>({ loading: true });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [attackersRes, contextRes] = await Promise.all([
          fetch(`/api/tc/graph/attackers/${assetId}`, { signal: AbortSignal.timeout(5000) }).then(r => r.json()).catch(() => ({})),
          fetch(`/api/tc/graph/context/${assetId}`, { signal: AbortSignal.timeout(5000) }).then(r => r.json()).catch(() => ({})),
        ]);
        if (!cancelled) {
          setData({
            attackers: attackersRes.attackers || [],
            cves: contextRes.cves || [],
            confidence: contextRes.confidence,
            blast: contextRes.blast_radius,
            loading: false,
          });
        }
      } catch {
        if (!cancelled) setData({ loading: false });
      }
    })();
    return () => { cancelled = true; };
  }, [assetId]);

  if (data.loading) {
    return <div style={{ marginTop: "10px", fontSize: "9px", color: "var(--tc-text-muted)", display: "flex", alignItems: "center", gap: "6px" }}><Loader2 size={10} className="animate-spin" /> Chargement intelligence graph...</div>;
  }

  const hasData = (data.attackers && data.attackers.length > 0) || (data.cves && data.cves.length > 0) || data.confidence != null;
  if (!hasData) return null;

  return (
    <div style={{ marginTop: "12px", borderTop: "1px solid var(--tc-border)", paddingTop: "10px" }}>
      <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-red)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
        <Shield size={11} /> Intelligence Graph
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "10px", fontSize: "10px" }}>
        {/* Confidence */}
        {data.confidence != null && (
          <div>
            <div style={{ color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Indice de confiance</div>
            <div style={{ fontSize: "16px", fontWeight: 800, color: data.confidence > 70 ? "#30a050" : data.confidence > 40 ? "var(--tc-amber)" : "var(--tc-text-muted)", marginTop: "2px" }}>
              {Math.round(data.confidence)}%
            </div>
          </div>
        )}

        {/* Attackers */}
        <div>
          <div style={{ color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Attaquants</div>
          <div style={{ fontSize: "16px", fontWeight: 800, color: (data.attackers?.length || 0) > 0 ? "#e04040" : "#30a050", marginTop: "2px" }}>
            {data.attackers?.length || 0}
          </div>
        </div>

        {/* CVEs */}
        <div>
          <div style={{ color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.05em" }}>CVEs affectant</div>
          <div style={{ fontSize: "16px", fontWeight: 800, color: (data.cves?.length || 0) > 0 ? "var(--tc-amber)" : "#30a050", marginTop: "2px" }}>
            {data.cves?.length || 0}
          </div>
        </div>
      </div>

      {/* Attacker IPs list */}
      {data.attackers && data.attackers.length > 0 && (
        <div style={{ marginTop: "8px" }}>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginBottom: "4px" }}>IPs attaquantes :</div>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {data.attackers.slice(0, 10).map((a: any, i: number) => (
              <span key={i} style={{ fontSize: "9px", fontFamily: "monospace", padding: "1px 6px", borderRadius: "3px", background: "rgba(208,48,32,0.08)", color: "#e04040", border: "1px solid rgba(208,48,32,0.15)" }}>
                {a["ip.addr"] || a.addr || JSON.stringify(a).slice(0, 20)}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* CVE list */}
      {data.cves && data.cves.length > 0 && (
        <div style={{ marginTop: "8px" }}>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginBottom: "4px" }}>Vulnérabilités :</div>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {data.cves.slice(0, 8).map((c: any, i: number) => (
              <span key={i} style={{ fontSize: "9px", fontFamily: "monospace", padding: "1px 6px", borderRadius: "3px", background: "rgba(208,144,32,0.08)", color: "var(--tc-amber)", border: "1px solid rgba(208,144,32,0.15)" }}>
                {c["c.id"] || c.id || JSON.stringify(c).slice(0, 20)} {c["c.cvss"] ? `(${c["c.cvss"]})` : ""}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Low confidence hint */}
      {data.confidence != null && data.confidence < 50 && (
        <div style={{ marginTop: "8px", fontSize: "9px", color: "var(--tc-amber)", fontStyle: "italic" }}>
          Confiance faible — activez des sources supplémentaires (AD, pfSense, nmap) dans Skills pour enrichir cet asset.
        </div>
      )}
    </div>
  );
}
