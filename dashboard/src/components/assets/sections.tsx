"use client";

/**
 * Shared asset detail components — Phase 11h (2026-05-07).
 *
 * Lives outside the App Router routes on purpose: Next.js App Router
 * does not support importing named exports across `page.tsx` files
 * cleanly (the imports compile but the production bundle silently
 * fails to render). Hosting these reusable sections here lets both
 * the listing page (`/assets`) and the detail page (`/assets/[id]`)
 * use them without crossing route boundaries.
 */

import React, { useState, useEffect, useCallback } from "react";
import {
  Server, Monitor, Smartphone, Globe, Network, Printer, Cpu, Factory, Cloud, HelpCircle,
  Shield, RefreshCw, Loader2, AlertTriangle, CheckCircle2, ChevronRight, ChevronLeft,
} from "lucide-react";
import { t as tr, type Locale } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import type { Asset } from "@/lib/asset-shared";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#e84040", HIGH: "#d07020", MEDIUM: "var(--tc-amber)", LOW: "var(--tc-blue)",
  critical: "#e84040", high: "#d07020", medium: "var(--tc-amber)", low: "var(--tc-blue)",
};

const labelStyle: React.CSSProperties = {
  fontSize: "9px", fontWeight: 700, color: "var(--tc-text-muted)",
  textTransform: "uppercase" as const, letterSpacing: "0.05em",
  marginBottom: "3px", display: "block",
};

export function ExclusionPanel({ asset, onChanged }: { asset: Asset; onChanged: () => void }) {
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

export function SecurityTab({ assetId }: { assetId: string }) {
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

  if (loading) return <div style={{ textAlign: "center", padding: "20px", color: "var(--tc-text-muted)", fontSize: "10px" }}>{tr("assetsSections_loading", locale)}</div>;

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
            {typeof data.ssh_keys === "number" ? `${data.ssh_keys} ${tr("assetsSections_keysCount", locale)}` :
             Array.isArray(data.ssh_keys) ? `${data.ssh_keys.length} ${tr("assetsSections_keysCount", locale)}` :
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

export function AssetScanSurface({ asset }: { asset: any }) {
  const locale = useLocale();
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
  const ago = lastNmap ? relTimeShort(lastNmap.finished_at, locale) : null;

  const rescan = async () => {
    if (!ip) { setMsg(tr("assetsSections_noIpOnAsset", locale)); return; }
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
        setMsg(d.error || d.reason || tr("assetsSections_failure", locale));
      } else {
        setMsg(`${tr("assetsSections_scanStarted", locale)} #${d.scan_id}`);
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
          <>🔄 <strong>{tr("assetsSections_nmapScanRunning", locale)}</strong> {tr("assetsSections_onThisAsset", locale)}</>
        ) : lastNmap ? (
          <>{tr("assetsSections_lastNmapScan", locale)} <strong>{ago}</strong> · {(lastNmap.result_json?.open_ports_total ?? 0)} {tr("assetsSections_portsDetected", locale)}</>
        ) : (
          <>{tr("assetsSections_noNmapScanYet", locale)}</>
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
        <RefreshCw size={10} /> {tr("assetsSections_rescan", locale)}
      </button>
    </div>
  );
}

function relTimeShort(iso: string | null, locale: Locale): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return tr("assetsSections_justNow", locale);
  if (diff < 3_600_000) {
    const m = Math.floor(diff / 60_000);
    return locale === "fr" ? `il y a ${m} min` : `${m} min ago`;
  }
  if (diff < 86_400_000) {
    const h = Math.floor(diff / 3_600_000);
    return locale === "fr" ? `il y a ${h} h` : `${h} h ago`;
  }
  return new Date(iso).toLocaleDateString(locale === "fr" ? "fr-FR" : "en-US");
}

export function AssetFindings({ asset }: { asset: any }) {
  const locale = useLocale();
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      // This section is the asset's software VULNERABILITIES — only CVE findings
      // from the software-vuln scanner. Sigma detections (PowerShell, reflective
      // loader, ...) and ML/behavioral findings (DBSCAN clustering) are NOT
      // vulnerabilities and belong in Incidents, so they are filtered out here.
      // One fetch with a generous limit (the previous per-query loop re-fetched the
      // same unfiltered page and capped at 50, dropping an asset's vulns past it).
      const queries = [asset.name, ...(asset.ip_addresses || [])].filter(Boolean);
      const allFindings: any[] = [];
      const res = await fetch(`/api/tc/findings?limit=500`);
      if (res.ok) {
        const data = await res.json();
        for (const f of data.findings || []) {
          if (f.category !== "software-vuln") continue;
          const matchAsset = f.asset && queries.some((q) => f.asset === q || f.asset.includes(q));
          const matchIp = queries.some((q) => f.metadata?.agent_ip === q || f.metadata?.src_ip === q);
          if (matchAsset || matchIp) allFindings.push(f);
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
          <Shield size={12} /> {loading ? tr("assetsSections_loading", locale) : tr("assetsSections_viewVulnerabilities", locale)}
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
        {tr("assetsSections_vulnerabilitiesTitle", locale)} ({findings.length})
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

export function GraphIntelSection({ assetId }: { assetId: string }) {
  const locale = useLocale();
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
    return <div style={{ marginTop: "10px", fontSize: "9px", color: "var(--tc-text-muted)", display: "flex", alignItems: "center", gap: "6px" }}><Loader2 size={10} className="animate-spin" /> {tr("assetsSections_loadingGraphIntel", locale)}</div>;
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
            <div style={{ color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.05em" }}>{tr("assetsSections_confidenceScore", locale)}</div>
            <div style={{ fontSize: "16px", fontWeight: 800, color: data.confidence > 70 ? "#30a050" : data.confidence > 40 ? "var(--tc-amber)" : "var(--tc-text-muted)", marginTop: "2px" }}>
              {Math.round(data.confidence)}%
            </div>
          </div>
        )}

        {/* Observed sources — the backend now deduplicates by IP and
            returns event_count + max_severity_rank + any_internal, so we
            render `attackers.length` as the distinct IP count rather than
            the raw edge count (which used to surface "4268 attackers"
            for a single chatty LAN peer). */}
        <div>
          <div style={{ color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.05em" }}>{tr("assetsSections_observedSources", locale)}</div>
          <div style={{ fontSize: "16px", fontWeight: 800, color: (data.attackers?.length || 0) > 0 ? "#e04040" : "#30a050", marginTop: "2px" }}>
            {data.attackers?.length || 0}
          </div>
        </div>

        {/* CVEs */}
        <div>
          <div style={{ color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.05em" }}>{tr("assetsSections_affectingCves", locale)}</div>
          <div style={{ fontSize: "16px", fontWeight: 800, color: (data.cves?.length || 0) > 0 ? "var(--tc-amber)" : "#30a050", marginTop: "2px" }}>
            {data.cves?.length || 0}
          </div>
        </div>
      </div>

      {/* Observed IPs list — one badge per distinct IP with ×event_count.
          Color reflects worst-seen severity_rank (5=critical … 1=info)
          and whether the source is external. */}
      {data.attackers && data.attackers.length > 0 && (
        <div style={{ marginTop: "8px" }}>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginBottom: "4px" }}>{tr("assetsSections_observedIps", locale)}</div>
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {data.attackers.slice(0, 10).map((a: any, i: number) => {
              const addr = a["ip.addr"] || a.addr || "—";
              const count = Number(a.event_count ?? a["event_count"] ?? 0);
              const sevRank = Number(a.max_severity_rank ?? a["max_severity_rank"] ?? 0);
              const isInternal = (a.any_internal ?? a["any_internal"]) === true;
              // Severity colour scale: critical/high = red, medium = amber,
              // low/info = muted. External keeps the red accent regardless
              // of severity since "anyone on the Internet talking to this
              // asset" is itself a signal worth surfacing.
              let color = "var(--tc-text-muted)";
              let bg = "rgba(255,255,255,0.04)";
              let border = "1px solid var(--tc-border)";
              if (!isInternal || sevRank >= 4) {
                color = "#e04040";
                bg = "rgba(208,48,32,0.08)";
                border = "1px solid rgba(208,48,32,0.15)";
              } else if (sevRank >= 3) {
                color = "var(--tc-amber)";
                bg = "rgba(234,179,8,0.08)";
                border = "1px solid rgba(234,179,8,0.20)";
              }
              return (
                <span key={i} title={isInternal ? tr("assetsSections_internalSource", locale) : tr("assetsSections_externalSource", locale)}
                  style={{ fontSize: "9px", fontFamily: "monospace", padding: "1px 6px", borderRadius: "3px", background: bg, color, border }}>
                  {addr}{count > 1 ? ` ×${count}` : ""}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* CVE list */}
      {data.cves && data.cves.length > 0 && (
        <div style={{ marginTop: "8px" }}>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginBottom: "4px" }}>{tr("assetsSections_vulnerabilitiesLabel", locale)}</div>
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
          {tr("assetsSections_lowConfidenceHint", locale)}
        </div>
      )}
    </div>
  );
}

