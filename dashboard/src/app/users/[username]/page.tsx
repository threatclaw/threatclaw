"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Users, Shield, AlertTriangle, ArrowLeft, Server, Activity, GitBranch } from "lucide-react";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { PageShell } from "@/components/chrome/PageShell";

interface UserSummary {
  username: string;
  is_admin: boolean;
  is_service_account: boolean;
  department: string | null;
  last_seen: string | null;
  login_count: number;
  failed_login_count: number;
  linked_assets: number;
}
interface LinkedAsset {
  asset_id: string; hostname: string | null; criticality: string | null;
  login_count: number; failed_login_count: number; last_login: string | null;
}
interface LoginEvent {
  asset_id: string; asset_hostname: string | null; source_ip: string;
  protocol: string; success: boolean; timestamp: string;
}
interface Anomaly {
  anomaly_type: string; username: string; detail: string; severity: string; confidence: number;
}
interface Escalation {
  from_user: string; to_user: string; method: string; asset: string; timestamp: string;
}
interface UserDetail {
  summary: UserSummary;
  linked_assets: LinkedAsset[];
  recent_logins: LoginEvent[];
  anomalies: Anomaly[];
  escalations_out: Escalation[];
  escalations_in: Escalation[];
}

const SEV_COLORS: Record<string, string> = {
  critical: "var(--tc-red)", high: "var(--tc-red)",
  medium: "var(--tc-amber)", low: "var(--tc-text-sec)",
};

const CRIT_COLORS: Record<string, string> = {
  critical: "#e04040", high: "#d07020", medium: "#d09020", low: "#30a050",
};

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("fr-FR", {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch { return iso; }
}

function SeverityPill({ severity }: { severity: string }) {
  const c = SEV_COLORS[severity.toLowerCase()] ?? "var(--tc-text-muted)";
  return (
    <span style={{
      display: "inline-block", padding: "2px 6px", fontSize: "9px",
      fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em",
      color: c, border: `1px solid ${c}`, borderRadius: "3px",
    }}>{severity}</span>
  );
}

export default function UserDetailPage() {
  const params = useParams<{ username: string }>();
  const username = decodeURIComponent(params?.username ?? "");
  const [data, setData] = useState<UserDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!username) return;
    setLoading(true); setError(null);
    fetch(`/api/tc/users/${encodeURIComponent(username)}`, { signal: AbortSignal.timeout(15000) })
      .then(async (r) => {
        if (!r.ok) throw new Error(r.status === 404 ? "Utilisateur introuvable" : `HTTP ${r.status}`);
        return r.json();
      })
      .then((d: UserDetail) => setData(d))
      .catch((e) => setError(e?.message ?? "fetch failed"))
      .finally(() => setLoading(false));
  }, [username]);

  const tags = (
    <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
      {data?.summary.is_admin && (
        <span style={{
          padding: "2px 6px", fontSize: "9px", fontWeight: 700,
          color: "var(--tc-red)", border: "1px solid var(--tc-red)",
          textTransform: "uppercase", letterSpacing: "0.08em", borderRadius: "3px",
        }}>Admin</span>
      )}
      {data?.summary.is_service_account && (
        <span style={{
          padding: "2px 6px", fontSize: "9px", fontWeight: 700,
          color: "var(--tc-text-sec)", border: "1px solid var(--tc-border)",
          textTransform: "uppercase", letterSpacing: "0.08em", borderRadius: "3px",
        }}>Service</span>
      )}
      <Link href="/users" style={{
        color: "var(--tc-text-sec)", display: "inline-flex", alignItems: "center", gap: "4px",
        fontSize: "11px", textDecoration: "none",
      }}>
        <ArrowLeft size={11} /> Retour
      </Link>
    </div>
  );

  return (
    <PageShell
      title={`Utilisateur · ${username}`}
      subtitle={data?.summary.department ? `Département : ${data.summary.department}` : undefined}
      right={tags}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

        {error && <ErrorBanner message={error} />}
        {loading && !data && (
          <div style={{ padding: "40px", textAlign: "center", color: "var(--tc-text-muted)", fontSize: "11px" }}>
            Chargement…
          </div>
        )}

        {data && (
          <>
            {/* Profile + stats */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "12px" }}>
              <KV label="Département" value={data.summary.department ?? "—"} />
              <KV label="Logins OK" value={String(data.summary.login_count - data.summary.failed_login_count)} />
              <KV label="Échecs" value={String(data.summary.failed_login_count)}
                  color={data.summary.failed_login_count > 0 ? "var(--tc-red)" : undefined} />
              <KV label="Assets" value={String(data.summary.linked_assets)} />
              <KV label="Dernière activité" value={fmtDate(data.summary.last_seen)} />
            </div>

            {/* Anomalies */}
            {data.anomalies.length > 0 && (
              <NeuCard style={{ padding: "16px" }}>
                <SectionTitle icon={AlertTriangle} label={`Anomalies UBA (${data.anomalies.length})`} />
                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  {data.anomalies.map((a, i) => (
                    <div key={i} style={{
                      display: "flex", alignItems: "center", gap: "10px",
                      padding: "8px 10px", background: "var(--tc-input)",
                      borderLeft: `3px solid ${SEV_COLORS[a.severity.toLowerCase()] ?? "var(--tc-text-muted)"}`,
                      borderRadius: "3px",
                    }}>
                      <SeverityPill severity={a.severity} />
                      <span style={{ fontSize: "11px", color: "var(--tc-text)" }}>{a.detail}</span>
                      <span style={{ marginLeft: "auto", fontSize: "10px", color: "var(--tc-text-muted)" }}>
                        {a.anomaly_type} · conf. {a.confidence}%
                      </span>
                    </div>
                  ))}
                </div>
              </NeuCard>
            )}

            {/* Escalations */}
            {(data.escalations_out.length > 0 || data.escalations_in.length > 0) && (
              <NeuCard style={{ padding: "16px" }}>
                <SectionTitle icon={GitBranch} label={`Escalades (${data.escalations_out.length + data.escalations_in.length})`} />
                <div style={{ display: "flex", flexDirection: "column", gap: "4px", fontSize: "11px" }}>
                  {data.escalations_out.map((e, i) => (
                    <div key={`o${i}`} style={{ color: "var(--tc-text-sec)" }}>
                      <span style={{ color: "var(--tc-red)", fontWeight: 700 }}>→</span>{" "}
                      <Link href={`/users/${encodeURIComponent(e.to_user)}`} style={{ color: "var(--tc-text)", fontWeight: 600, textDecoration: "none" }}>
                        {e.to_user}
                      </Link>
                      {" "}via <code style={{ fontSize: "10px" }}>{e.method}</code> sur {e.asset}
                      <span style={{ color: "var(--tc-text-muted)", marginLeft: "8px" }}>{fmtDate(e.timestamp)}</span>
                    </div>
                  ))}
                  {data.escalations_in.map((e, i) => (
                    <div key={`i${i}`} style={{ color: "var(--tc-text-sec)" }}>
                      <span style={{ color: "var(--tc-amber)", fontWeight: 700 }}>←</span>{" "}
                      <Link href={`/users/${encodeURIComponent(e.from_user)}`} style={{ color: "var(--tc-text)", fontWeight: 600, textDecoration: "none" }}>
                        {e.from_user}
                      </Link>
                      {" "}via <code style={{ fontSize: "10px" }}>{e.method}</code> sur {e.asset}
                      <span style={{ color: "var(--tc-text-muted)", marginLeft: "8px" }}>{fmtDate(e.timestamp)}</span>
                    </div>
                  ))}
                </div>
              </NeuCard>
            )}

            {/* Linked assets */}
            <NeuCard style={{ padding: 0, overflow: "hidden" }}>
              <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--tc-border)" }}>
                <SectionTitle icon={Server} label={`Assets accédés (${data.linked_assets.length})`} />
              </div>
              {data.linked_assets.length === 0 ? (
                <div style={{ padding: "20px", textAlign: "center", color: "var(--tc-text-muted)", fontSize: "11px" }}>
                  Aucun asset lié.
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
                  <thead>
                    <tr style={{ background: "var(--tc-input)" }}>
                      <Th>Asset</Th>
                      <Th>Criticité</Th>
                      <Th align="right">Logins</Th>
                      <Th align="right">Échecs</Th>
                      <Th>Dernier login</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.linked_assets.map((a) => (
                      <tr key={a.asset_id} style={{ borderTop: "1px solid var(--tc-border)" }}>
                        <Td>
                          <Link href={`/assets?id=${encodeURIComponent(a.asset_id)}`} style={{ color: "var(--tc-text)", fontWeight: 600, textDecoration: "none" }}>
                            {a.hostname ?? a.asset_id}
                          </Link>
                        </Td>
                        <Td>
                          {a.criticality ? (
                            <span style={{
                              padding: "2px 6px", fontSize: "9px", fontWeight: 700,
                              color: CRIT_COLORS[a.criticality.toLowerCase()] ?? "var(--tc-text-muted)",
                              border: `1px solid ${CRIT_COLORS[a.criticality.toLowerCase()] ?? "var(--tc-border)"}`,
                              textTransform: "uppercase", letterSpacing: "0.08em", borderRadius: "3px",
                            }}>{a.criticality}</span>
                          ) : "—"}
                        </Td>
                        <Td align="right"><span style={{ fontVariantNumeric: "tabular-nums" }}>{a.login_count}</span></Td>
                        <Td align="right">
                          <span style={{
                            fontVariantNumeric: "tabular-nums",
                            color: a.failed_login_count > 0 ? "var(--tc-red)" : "var(--tc-text-muted)",
                          }}>{a.failed_login_count}</span>
                        </Td>
                        <Td>{fmtDate(a.last_login)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </NeuCard>

            {/* Recent logins */}
            <NeuCard style={{ padding: 0, overflow: "hidden" }}>
              <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--tc-border)" }}>
                <SectionTitle icon={Activity} label={`Connexions récentes (${data.recent_logins.length})`} />
              </div>
              {data.recent_logins.length === 0 ? (
                <div style={{ padding: "20px", textAlign: "center", color: "var(--tc-text-muted)", fontSize: "11px" }}>
                  Aucun événement de connexion.
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
                  <thead>
                    <tr style={{ background: "var(--tc-input)" }}>
                      <Th>Horodatage</Th>
                      <Th>Asset</Th>
                      <Th>Source IP</Th>
                      <Th>Protocole</Th>
                      <Th>Résultat</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent_logins.map((l, i) => (
                      <tr key={i} style={{ borderTop: "1px solid var(--tc-border)" }}>
                        <Td>{fmtDate(l.timestamp)}</Td>
                        <Td>{l.asset_hostname ?? l.asset_id}</Td>
                        <Td><code style={{ fontSize: "10px", color: "var(--tc-text)" }}>{l.source_ip || "—"}</code></Td>
                        <Td>{l.protocol || "—"}</Td>
                        <Td>
                          {l.success ? (
                            <span style={{ color: "var(--tc-green, #30a050)", fontWeight: 700, fontSize: "10px" }}>OK</span>
                          ) : (
                            <span style={{ color: "var(--tc-red)", fontWeight: 700, fontSize: "10px" }}>ÉCHEC</span>
                          )}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </NeuCard>
          </>
        )}
      </div>
    </PageShell>
  );
}

function SectionTitle({ icon: Icon, label }: { icon: React.ElementType; label: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
      <Icon size={12} color="var(--tc-text-sec)" />
      <span style={{ fontSize: "10px", fontWeight: 700, color: "var(--tc-text-sec)", textTransform: "uppercase", letterSpacing: "0.14em" }}>
        {label}
      </span>
    </div>
  );
}

function KV({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <NeuCard style={{ padding: "12px" }}>
      <div style={{ fontSize: "9px", fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.14em", marginBottom: "6px" }}>
        {label}
      </div>
      <div style={{ fontSize: "13px", fontWeight: 700, color: color ?? "var(--tc-text)", fontVariantNumeric: "tabular-nums" }}>
        {value}
      </div>
    </NeuCard>
  );
}

function Th({ children, align }: { children?: React.ReactNode; align?: "left" | "right" }) {
  return (
    <th style={{
      padding: "8px 10px", textAlign: align ?? "left",
      fontSize: "9px", fontWeight: 700, textTransform: "uppercase",
      letterSpacing: "0.12em", color: "var(--tc-text-muted)",
    }}>{children}</th>
  );
}

function Td({ children, align }: { children?: React.ReactNode; align?: "left" | "right" }) {
  return (
    <td style={{
      padding: "10px", textAlign: align ?? "left",
      color: "var(--tc-text-sec)", verticalAlign: "middle",
    }}>{children}</td>
  );
}
