"use client";

import React, { useEffect, useState } from "react";
import { Shield, Brain, Database, AlertTriangle, Radio, Cpu, Eye, Activity } from "lucide-react";

interface HealthData { status: string; version: string; database: boolean; llm: string; disk_free: string; ml?: { alive: boolean; model_trained: boolean; data_days: number }; }
interface Finding { id: number; title: string; severity: string; asset?: string; source?: string; }

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 11, fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.15em", color: "#d03020", margin: "32px 0 14px", borderBottom: "1px solid rgba(208,48,32,0.15)", paddingBottom: 8 }}>{children}</div>;
}

// ══════════════════════════════════════════════════════════════
//  SCORE — 4 variantes
// ══════════════════════════════════════════════════════════════

function Score_A({ score }: { score: number }) {
  const color = score >= 80 ? "#30a050" : score >= 50 ? "#d09020" : "#d03020";
  const r = 65; const circ = 2 * Math.PI * r; const dash = (score / 100) * circ * 0.75;
  return (
    <div style={{ background: "linear-gradient(160deg, #1c1c26 0%, #141418 50%, #1a1422 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px", textAlign: "center", position: "relative", overflow: "hidden" }}>
      <div style={{ position: "absolute", top: "25%", left: "50%", transform: "translate(-50%,-50%)", width: 200, height: 200, background: `radial-gradient(circle, ${color}12 0%, transparent 70%)`, pointerEvents: "none" }} />
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 12 }}>Tuile 1 — Arc Glow</div>
      <div style={{ position: "relative", width: 160, height: 160, margin: "0 auto" }}>
        <svg width="160" height="160" viewBox="0 0 160 160">
          <circle cx="80" cy="80" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={7} />
          <circle cx="80" cy="80" r={r} fill="none" stroke={color} strokeWidth={7} strokeDasharray={`${dash} ${circ}`} strokeDashoffset={circ * 0.25} strokeLinecap="round" transform="rotate(-225 80 80)" style={{ filter: `drop-shadow(0 0 10px ${color}50)` }} />
          {Array.from({ length: 20 }).map((_, i) => { const a = (-225 + i * (270 / 20)) * (Math.PI / 180); return <line key={i} x1={80 + (r + 8) * Math.cos(a)} y1={80 + (r + 8) * Math.sin(a)} x2={80 + (r + 13) * Math.cos(a)} y2={80 + (r + 13) * Math.sin(a)} stroke="rgba(255,255,255,0.08)" strokeWidth={1} />; })}
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <span style={{ fontSize: 44, fontWeight: 900, color, letterSpacing: -2 }}>{score}</span>
          <span style={{ fontSize: 9, color: "#6B7280" }}>/ 100</span>
        </div>
      </div>
    </div>
  );
}

function Score_B({ score }: { score: number }) {
  const color = score >= 80 ? "#30a050" : "#d03020";
  return (
    <div style={{ background: "linear-gradient(135deg, #18181e 0%, #1e1424 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px", textAlign: "center", position: "relative", overflow: "hidden" }}>
      {/* Circuit dots */}
      <svg style={{ position: "absolute", inset: 0, width: "100%", height: "100%", opacity: 0.4 }}>
        {Array.from({ length: 40 }).map((_, i) => {
          const x = 15 + (i % 8) * 30; const y = 15 + Math.floor(i / 8) * 30;
          const active = Math.random() > 0.5;
          return <circle key={i} cx={x} cy={y} r={active ? 2 : 1} fill={active ? color : "#2a2a2a"} opacity={active ? 0.6 : 0.3}>
            {active && <animate attributeName="opacity" values="0.2;0.8;0.2" dur={`${1.5 + Math.random() * 2}s`} repeatCount="indefinite" />}
          </circle>;
        })}
      </svg>
      <div style={{ position: "relative", zIndex: 1 }}>
        <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 16 }}>Tuile 2 — Circuit Board</div>
        <div style={{ fontSize: 64, fontWeight: 900, color, letterSpacing: -3, lineHeight: 1, textShadow: `0 0 30px ${color}40` }}>{score}</div>
        <div style={{ width: "80%", height: 4, margin: "16px auto 0", background: "rgba(255,255,255,0.04)", borderRadius: 2, overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${score}%`, background: `linear-gradient(90deg, ${color}40, ${color})`, borderRadius: 2, boxShadow: `0 0 8px ${color}40` }} />
        </div>
        <div style={{ fontSize: 10, color: "#6B7280", marginTop: 8 }}>Situation {score >= 80 ? "stable" : "critique"}</div>
      </div>
    </div>
  );
}

function Score_C({ score }: { score: number }) {
  const color = score >= 80 ? "#30a050" : "#d03020";
  const r = 55; const circ = Math.PI * r;
  return (
    <div style={{ background: "linear-gradient(180deg, #1a1a24 0%, #12121e 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px", textAlign: "center" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 16 }}>Tuile 3 — Speedometer</div>
      <div style={{ position: "relative", width: 160, height: 100, margin: "0 auto" }}>
        <svg width="160" height="100" viewBox="0 0 160 100">
          <defs><linearGradient id="spGrad"><stop offset="0%" stopColor="#d03020" /><stop offset="50%" stopColor="#d09020" /><stop offset="100%" stopColor="#30a050" /></linearGradient></defs>
          <path d={`M ${80 - r} 85 A ${r} ${r} 0 0 1 ${80 + r} 85`} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={10} strokeLinecap="round" />
          <path d={`M ${80 - r} 85 A ${r} ${r} 0 0 1 ${80 + r} 85`} fill="none" stroke="url(#spGrad)" strokeWidth={10} strokeLinecap="round" strokeDasharray={`${(score / 100) * circ} ${circ}`} />
          {/* Needle */}
          {(() => { const angle = Math.PI - (score / 100) * Math.PI; const nx = 80 + 40 * Math.cos(angle); const ny = 85 - 40 * Math.sin(angle); return <><line x1="80" y1="85" x2={nx} y2={ny} stroke="#fff" strokeWidth={2} strokeLinecap="round" /><circle cx="80" cy="85" r="4" fill="#1a1a24" stroke="#fff" strokeWidth={1.5} /></>; })()}
        </svg>
        <div style={{ position: "absolute", bottom: 0, left: "50%", transform: "translateX(-50%)" }}>
          <span style={{ fontSize: 28, fontWeight: 900, color: "#fff" }}>{score}</span>
          <span style={{ fontSize: 10, color: "#6B7280" }}> pts</span>
        </div>
      </div>
    </div>
  );
}

function Score_D({ score }: { score: number }) {
  const color = score >= 80 ? "#30a050" : "#d03020";
  const segments = 20;
  return (
    <div style={{ background: "linear-gradient(160deg, #1c1c24 0%, #161620 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px", textAlign: "center" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 16 }}>Tuile 4 — Segmented Ring</div>
      <div style={{ position: "relative", width: 160, height: 160, margin: "0 auto" }}>
        <svg width="160" height="160" viewBox="0 0 160 160">
          {Array.from({ length: segments }).map((_, i) => {
            const a1 = (-225 + i * (270 / segments)) * (Math.PI / 180);
            const a2 = (-225 + (i + 0.7) * (270 / segments)) * (Math.PI / 180);
            const filled = i < (score / 100) * segments;
            const segColor = filled ? (i < segments * 0.3 ? "#d03020" : i < segments * 0.6 ? "#d09020" : "#30a050") : "rgba(255,255,255,0.04)";
            return <path key={i} d={`M${80 + 55 * Math.cos(a1)},${80 + 55 * Math.sin(a1)} A55,55 0 0,1 ${80 + 55 * Math.cos(a2)},${80 + 55 * Math.sin(a2)}`} fill="none" stroke={segColor} strokeWidth={8} strokeLinecap="round" style={filled ? { filter: `drop-shadow(0 0 4px ${segColor}40)` } : {}} />;
          })}
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <Shield size={20} color={color} />
          <span style={{ fontSize: 36, fontWeight: 900, color, marginTop: 4 }}>{score}</span>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
//  PIPELINE — 4 variantes
// ══════════════════════════════════════════════════════════════

function Pipeline_A({ ok, ai, n }: { ok: boolean; ai: boolean; n: number }) {
  const srcs = ["Wazuh", "Suricata", "FluentBit", "Nuclei", "Connect."];
  const act = [true, true, true, false, true];
  return (
    <div style={{ background: "linear-gradient(160deg, #181822 0%, #12121a 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "20px", position: "relative", overflow: "hidden" }}>
      <div style={{ position: "absolute", inset: 0, backgroundImage: "linear-gradient(rgba(208,48,32,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(208,48,32,0.02) 1px, transparent 1px)", backgroundSize: "30px 30px" }} />
      <div style={{ position: "relative", zIndex: 1 }}>
        <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 10 }}>Tuile 1 — Sankey Grid</div>
        <svg width="100%" height="180" viewBox="0 0 500 180">
          <defs><linearGradient id="p1a"><stop offset="0%" stopColor="#d03020" stopOpacity="0.7" /><stop offset="100%" stopColor="#d03020" stopOpacity="0.15" /></linearGradient></defs>
          {srcs.map((s, i) => { const y = 15 + i * 36; const a = act[i]; return (
            <g key={i}>
              <path d={`M60,${y} C140,${y} 160,90 210,90`} fill="none" stroke={a ? "url(#p1a)" : "#222"} strokeWidth={a ? 2.5 : 1} opacity={a ? 1 : 0.3} strokeLinecap="round" />
              {a && <circle r={2} fill="#d03020" opacity={0.8}><animateMotion dur="2s" repeatCount="indefinite" path={`M60,${y} C140,${y} 160,90 210,90`} /></circle>}
              <rect x={2} y={y - 9} width={54} height={18} rx={5} fill={a ? "rgba(208,48,32,0.06)" : "rgba(255,255,255,0.01)"} stroke={a ? "rgba(208,48,32,0.12)" : "rgba(255,255,255,0.03)"} strokeWidth={0.5} />
              <text x={29} y={y + 3} fill={a ? "#d03020" : "#333"} fontSize="7" fontWeight="700" textAnchor="middle">{s}</text>
            </g>
          ); })}
          <line x1="240" y1="90" x2="320" y2="90" stroke={ok ? "#d03020" : "#333"} strokeWidth={2} opacity={0.5} />
          <line x1="370" y1="90" x2="440" y2="90" stroke={ai ? "#30a050" : "#333"} strokeWidth={2} opacity={0.5} />
          {ok && <circle r={2} fill="#d03020"><animateMotion dur="1.2s" repeatCount="indefinite" path="M240,90 L320,90" /></circle>}
          {ai && <circle r={2} fill="#30a050"><animateMotion dur="1.5s" repeatCount="indefinite" path="M370,90 L440,90" /></circle>}
          {[{ x: 225, l: "IE", c: "#d03020", a: ok }, { x: 345, l: "AI", c: "#d03020", a: ai }, { x: 455, l: "OUT", c: "#30a050", a: ok }].map(nd => (
            <g key={nd.l}><circle cx={nd.x} cy={90} r={20} fill="#16161e" stroke={nd.a ? nd.c : "#333"} strokeWidth={1.5} />{nd.a && <circle cx={nd.x} cy={90} r={28} fill="none" stroke={nd.c} strokeWidth={0.3} opacity={0.3} />}<text x={nd.x} y={93} fill={nd.a ? "#fff" : "#444"} fontSize="9" fontWeight="800" textAnchor="middle" dominantBaseline="middle">{nd.l}</text></g>
          ))}
          <text x={455} y={60} fill="#d03020" fontSize="12" fontWeight="900" textAnchor="middle">{n}</text>
        </svg>
      </div>
    </div>
  );
}

function Pipeline_B({ ok, ai, n }: { ok: boolean; ai: boolean; n: number }) {
  const steps = [{ l: "COLLECTE", s: "5 sources", a: true, c: "#d03020" }, { l: "IE", s: "Scoring", a: ok, c: "#d03020" }, { l: "REACT", s: "Investigation", a: ai, c: "#d09020" }, { l: "VERDICT", s: `${n} findings`, a: ok, c: "#30a050" }];
  return (
    <div style={{ background: "linear-gradient(160deg, #1a1a24 0%, #141420 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 16 }}>Tuile 2 — Steps Horizontal</div>
      <div style={{ display: "flex", alignItems: "center", gap: 0 }}>
        {steps.map((st, i) => (
          <React.Fragment key={i}>
            <div style={{ flex: 1, textAlign: "center" }}>
              <div style={{ width: 44, height: 44, borderRadius: "50%", margin: "0 auto", background: st.a ? `${st.c}15` : "rgba(255,255,255,0.02)", border: `2px solid ${st.a ? st.c : "#333"}`, display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
                {st.a && <div style={{ position: "absolute", inset: -6, borderRadius: "50%", border: `1px solid ${st.c}20` }}><div style={{ position: "absolute", inset: -4, borderRadius: "50%", border: `1px solid ${st.c}10` }} /></div>}
                <span style={{ fontSize: 10, fontWeight: 800, color: st.a ? "#fff" : "#444" }}>{st.l.charAt(0)}</span>
              </div>
              <div style={{ fontSize: 9, fontWeight: 700, color: st.a ? st.c : "#444", marginTop: 8 }}>{st.l}</div>
              <div style={{ fontSize: 8, color: "#6B7280", marginTop: 2 }}>{st.s}</div>
            </div>
            {i < steps.length - 1 && (
              <div style={{ width: 40, height: 2, background: steps[i + 1].a ? `linear-gradient(90deg, ${st.c}60, ${steps[i + 1].c}60)` : "#222", position: "relative" }}>
                {steps[i + 1].a && <div style={{ position: "absolute", width: 6, height: 6, borderRadius: "50%", background: st.c, top: -2, animation: `moveRight${i} 1.5s linear infinite` }}><style>{`@keyframes moveRight${i} { from { left: 0 } to { left: 34px } }`}</style></div>}
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

function Pipeline_C({ ok, ai, n }: { ok: boolean; ai: boolean; n: number }) {
  return (
    <div style={{ background: "linear-gradient(160deg, #1c1c26 0%, #14141e 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 16 }}>Tuile 3 — Vertical Flow</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
        {[{ l: "5 Sources actives", d: "Wazuh · Suricata · FluentBit · Connectors", c: "#d03020", a: true },
          { l: "Intelligence Engine", d: "Scoring · Correlation · Enrichissement", c: "#d03020", a: ok },
          { l: "AI Investigation", d: "L1 Triage · L2 Forensique · Skills", c: "#d09020", a: ai },
          { l: `${n} Verdicts`, d: "Notification RSSI · HITL · Actions", c: "#30a050", a: ok }
        ].map((st, i) => (
          <React.Fragment key={i}>
            <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "10px 12px", background: st.a ? `${st.c}08` : "transparent", borderRadius: 10, border: `1px solid ${st.a ? st.c + "15" : "transparent"}`, borderLeft: `3px solid ${st.a ? st.c : "#333"}` }}>
              <div style={{ width: 28, height: 28, borderRadius: 8, background: st.a ? `${st.c}15` : "rgba(255,255,255,0.02)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <span style={{ fontSize: 12, fontWeight: 900, color: st.a ? st.c : "#444" }}>{i + 1}</span>
              </div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: st.a ? "#fff" : "#444" }}>{st.l}</div>
                <div style={{ fontSize: 8, color: "#6B7280", marginTop: 2 }}>{st.d}</div>
              </div>
              {st.a && <span style={{ marginLeft: "auto", width: 6, height: 6, borderRadius: "50%", background: st.c, boxShadow: `0 0 6px ${st.c}` }} />}
            </div>
            {i < 3 && <div style={{ width: 2, height: 16, background: st.a ? `linear-gradient(180deg, ${st.c}40, transparent)` : "#222", marginLeft: 24 }} />}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

function Pipeline_D({ ok, ai, n }: { ok: boolean; ai: boolean; n: number }) {
  return (
    <div style={{ background: "linear-gradient(160deg, #181820 0%, #121218 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px", position: "relative", overflow: "hidden" }}>
      {/* Animated scan line */}
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1, background: "linear-gradient(90deg, transparent, rgba(208,48,32,0.3), transparent)", animation: "scanPD 4s linear infinite" }} />
      <style>{`@keyframes scanPD { from { top: 0 } to { top: 100% } }`}</style>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 16 }}>Tuile 4 — Matrix Cards</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10 }}>
        {[{ l: "COLLECT", v: "5", s: "sources", c: "#d03020", a: true }, { l: "SCORE", v: "95", s: "IE score", c: "#d03020", a: ok }, { l: "REACT", v: ai ? "L2" : "--", s: "level", c: "#d09020", a: ai }, { l: "OUTPUT", v: String(n), s: "findings", c: "#30a050", a: ok }].map(st => (
          <div key={st.l} style={{ background: st.a ? `${st.c}08` : "rgba(255,255,255,0.01)", border: `1px solid ${st.a ? st.c + "20" : "rgba(255,255,255,0.04)"}`, borderRadius: 12, padding: "14px 10px", textAlign: "center" }}>
            <div style={{ fontSize: 8, fontWeight: 700, color: st.a ? st.c : "#444", letterSpacing: "0.1em" }}>{st.l}</div>
            <div style={{ fontSize: 24, fontWeight: 900, color: st.a ? "#fff" : "#333", marginTop: 6, textShadow: st.a ? `0 0 10px ${st.c}30` : "none" }}>{st.v}</div>
            <div style={{ fontSize: 8, color: "#6B7280", marginTop: 4 }}>{st.s}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
//  HUB — 4 variantes
// ══════════════════════════════════════════════════════════════

function Hub_A({ svcs }: { svcs: { l: string; ok: boolean; d: string; a: number }[] }) {
  const s = 260; const c = s / 2; const nr = 105;
  return (
    <div style={{ background: "linear-gradient(160deg, #1a1a26 0%, #141420 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "20px", textAlign: "center" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 8 }}>Tuile 1 — Orbital</div>
      <div style={{ position: "relative", width: s, height: s, margin: "0 auto" }}>
        <svg width={s} height={s}>
          <circle cx={c} cy={c} r={55} fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth={0.5} /><circle cx={c} cy={c} r={85} fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth={0.5} strokeDasharray="3,5" />
          {svcs.map(sv => { const rad = (sv.a * Math.PI) / 180; const x = c + nr * Math.cos(rad); const y = c + nr * Math.sin(rad); const col = sv.ok ? "#30a050" : "#d03020"; return (
            <g key={sv.l}><line x1={c} y1={c} x2={x} y2={y} stroke={col} strokeWidth={1.5} opacity={0.4} strokeDasharray={sv.ok ? "none" : "3,3"} />{sv.ok && <><circle r={2} fill={col} opacity={0.7}><animateMotion dur="3s" repeatCount="indefinite" path={`M${c},${c} L${x},${y}`} /></circle><circle cx={x} cy={y} r={6} fill="none" stroke={col} strokeWidth={0.5} opacity={0.3}><animate attributeName="r" values="6;12;6" dur="2s" repeatCount="indefinite" /><animate attributeName="opacity" values="0.3;0;0.3" dur="2s" repeatCount="indefinite" /></circle></>}</g>
          ); })}
          <circle cx={c} cy={c} r={30} fill="radial-gradient(circle, rgba(208,48,32,0.1), transparent)" /><circle cx={c} cy={c} r={26} fill="#16161e" stroke="#d03020" strokeWidth={2} /><text x={c} y={c + 1} fill="#d03020" fontSize="11" fontWeight="900" textAnchor="middle" dominantBaseline="middle">TC</text>
        </svg>
        {svcs.map(sv => { const rad = (sv.a * Math.PI) / 180; const x = c + nr * Math.cos(rad) - 34; const y = c + nr * Math.sin(rad) - 14; const col = sv.ok ? "#30a050" : "#d03020"; return (
          <div key={sv.l} style={{ position: "absolute", left: x, top: y, width: 68, padding: "4px 6px", background: "rgba(18,18,26,0.9)", border: `1px solid ${col}25`, borderRadius: 8, textAlign: "center" }}>
            <div style={{ fontSize: 7, fontWeight: 700, color: col, textTransform: "uppercase" }}>{sv.l}</div>
            <div style={{ fontSize: 7, color: "#6B7280" }}>{sv.d}</div>
          </div>
        ); })}
      </div>
    </div>
  );
}

function Hub_B({ svcs }: { svcs: { l: string; ok: boolean; d: string; a: number }[] }) {
  return (
    <div style={{ background: "linear-gradient(160deg, #1c1c24 0%, #16161e 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 14 }}>Tuile 2 — Status List</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {svcs.map(sv => { const col = sv.ok ? "#30a050" : "#d03020"; return (
          <div key={sv.l} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", background: sv.ok ? "rgba(48,160,80,0.04)" : "rgba(208,48,32,0.04)", borderRadius: 10, border: `1px solid ${col}15` }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: col, boxShadow: `0 0 6px ${col}`, flexShrink: 0 }} />
            <span style={{ fontSize: 11, fontWeight: 700, color: "#e8e4e0", flex: 1 }}>{sv.l}</span>
            <span style={{ fontSize: 9, color: "#6B7280" }}>{sv.d}</span>
            <span style={{ fontSize: 8, fontWeight: 700, color: col, background: `${col}15`, padding: "2px 8px", borderRadius: 4 }}>{sv.ok ? "OK" : "DOWN"}</span>
          </div>
        ); })}
      </div>
    </div>
  );
}

function Hub_C({ svcs }: { svcs: { l: string; ok: boolean; d: string; a: number }[] }) {
  return (
    <div style={{ background: "linear-gradient(160deg, #181822 0%, #14141c 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 14 }}>Tuile 3 — Grid Tiles</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
        {svcs.map(sv => { const col = sv.ok ? "#30a050" : "#d03020"; return (
          <div key={sv.l} style={{ background: `${col}06`, border: `1px solid ${col}18`, borderRadius: 12, padding: "12px", textAlign: "center", position: "relative", overflow: "hidden" }}>
            {sv.ok && <div style={{ position: "absolute", top: 0, left: "50%", transform: "translateX(-50%)", width: 30, height: 2, background: col, borderRadius: 1, boxShadow: `0 0 8px ${col}` }} />}
            <div style={{ fontSize: 9, fontWeight: 800, color: col }}>{sv.l}</div>
            <div style={{ fontSize: 7, color: "#6B7280", marginTop: 4 }}>{sv.d}</div>
          </div>
        ); })}
      </div>
    </div>
  );
}

function Hub_D({ svcs }: { svcs: { l: string; ok: boolean; d: string; a: number }[] }) {
  const total = svcs.length; const online = svcs.filter(s => s.ok).length; const pct = (online / total) * 100;
  return (
    <div style={{ background: "linear-gradient(160deg, #1a1a24 0%, #141420 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px", textAlign: "center" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 16 }}>Tuile 4 — Uptime Ring</div>
      <div style={{ position: "relative", width: 120, height: 120, margin: "0 auto" }}>
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={6} />
          <circle cx="60" cy="60" r="50" fill="none" stroke="#30a050" strokeWidth={6} strokeDasharray={`${(pct / 100) * 314} 314`} strokeLinecap="round" transform="rotate(-90 60 60)" style={{ filter: "drop-shadow(0 0 6px rgba(48,160,80,0.4))" }} />
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <span style={{ fontSize: 24, fontWeight: 900, color: "#30a050" }}>{online}/{total}</span>
          <span style={{ fontSize: 8, color: "#6B7280" }}>services</span>
        </div>
      </div>
      <div style={{ display: "flex", justifyContent: "center", gap: 12, marginTop: 12, flexWrap: "wrap" }}>
        {svcs.map(sv => <span key={sv.l} style={{ fontSize: 8, color: sv.ok ? "#30a050" : "#d03020", fontWeight: 600 }}>{sv.l}</span>)}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
//  FINDINGS — 4 variantes
// ══════════════════════════════════════════════════════════════

function Findings_A({ counts }: { counts: { critical: number; high: number; medium: number; low: number } }) {
  const total = counts.critical + counts.high + counts.medium + counts.low || 1;
  const data = [{ l: "CRITICAL", v: counts.critical, c: "#d03020" }, { l: "HIGH", v: counts.high, c: "#e06030" }, { l: "MEDIUM", v: counts.medium, c: "#d09020" }, { l: "LOW", v: counts.low, c: "#4a5568" }];
  const r = 48; const circ = 2 * Math.PI * r; let off = 0;
  return (
    <div style={{ background: "linear-gradient(160deg, #1a1a24 0%, #16161e 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 14 }}>Tuile 1 — Donut</div>
      <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
        <div style={{ position: "relative", width: 110, height: 110, flexShrink: 0 }}>
          <svg width="110" height="110" viewBox="0 0 110 110">
            <circle cx="55" cy="55" r={r} fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth={12} />
            {data.map((d, i) => { const dl = (d.v / total) * circ; const co = off; off += dl; return dl > 0 ? <circle key={i} cx="55" cy="55" r={r} fill="none" stroke={d.c} strokeWidth={12} strokeDasharray={`${dl} ${circ - dl}`} strokeDashoffset={-co} transform="rotate(-90 55 55)" strokeLinecap="round" style={i === 0 ? { filter: `drop-shadow(0 0 6px ${d.c}40)` } : {}} /> : null; })}
          </svg>
          <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
            <span style={{ fontSize: 26, fontWeight: 900, color: "#fff" }}>{total}</span>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {data.map(d => <div key={d.l} style={{ display: "flex", alignItems: "center", gap: 6 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: d.c }} /><span style={{ fontSize: 9, color: "#6B7280", flex: 1 }}>{d.l}</span><span style={{ fontSize: 13, fontWeight: 800, color: "#fff" }}>{d.v}</span></div>)}
        </div>
      </div>
    </div>
  );
}

function Findings_B({ counts }: { counts: { critical: number; high: number; medium: number; low: number } }) {
  const max = Math.max(counts.critical, counts.high, counts.medium, counts.low, 1);
  const data = [{ l: "CRITICAL", v: counts.critical, c: "#d03020" }, { l: "HIGH", v: counts.high, c: "#e06030" }, { l: "MEDIUM", v: counts.medium, c: "#d09020" }, { l: "LOW", v: counts.low, c: "#4a5568" }];
  return (
    <div style={{ background: "linear-gradient(160deg, #1c1c26 0%, #161620 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 14 }}>Tuile 2 — Bars Gradient</div>
      {data.map(d => (
        <div key={d.l} style={{ marginBottom: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <span style={{ fontSize: 9, fontWeight: 700, color: d.c }}>{d.l}</span>
            <span style={{ fontSize: 13, fontWeight: 900, color: "#fff" }}>{d.v}</span>
          </div>
          <div style={{ height: 8, background: "rgba(255,255,255,0.03)", borderRadius: 4, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${(d.v / max) * 100}%`, background: `linear-gradient(90deg, ${d.c}30, ${d.c})`, borderRadius: 4, boxShadow: d.v > 0 ? `0 0 8px ${d.c}30` : "none" }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function Findings_C({ counts }: { counts: { critical: number; high: number; medium: number; low: number } }) {
  const data = [{ l: "CRIT", v: counts.critical, c: "#d03020" }, { l: "HIGH", v: counts.high, c: "#e06030" }, { l: "MED", v: counts.medium, c: "#d09020" }, { l: "LOW", v: counts.low, c: "#4a5568" }];
  return (
    <div style={{ background: "linear-gradient(160deg, #181822 0%, #141420 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 14 }}>Tuile 3 — Big Numbers</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        {data.map(d => (
          <div key={d.l} style={{ background: `${d.c}08`, border: `1px solid ${d.c}18`, borderRadius: 12, padding: "14px", textAlign: "center" }}>
            <div style={{ fontSize: 32, fontWeight: 900, color: d.c, lineHeight: 1, textShadow: `0 0 15px ${d.c}30` }}>{d.v}</div>
            <div style={{ fontSize: 8, fontWeight: 700, color: "#6B7280", marginTop: 6, letterSpacing: "0.1em" }}>{d.l}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Findings_D({ counts }: { counts: { critical: number; high: number; medium: number; low: number } }) {
  const total = counts.critical + counts.high + counts.medium + counts.low || 1;
  const data = [{ l: "CRITICAL", v: counts.critical, c: "#d03020" }, { l: "HIGH", v: counts.high, c: "#e06030" }, { l: "MEDIUM", v: counts.medium, c: "#d09020" }, { l: "LOW", v: counts.low, c: "#4a5568" }];
  return (
    <div style={{ background: "linear-gradient(160deg, #1a1a26 0%, #14141e 100%)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 20, padding: "24px" }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "#6B7280", marginBottom: 14 }}>Tuile 4 — Stacked Bar</div>
      <div style={{ textAlign: "center", marginBottom: 12 }}>
        <span style={{ fontSize: 36, fontWeight: 900, color: "#fff" }}>{total}</span>
        <span style={{ fontSize: 11, color: "#6B7280", marginLeft: 4 }}>findings</span>
      </div>
      <div style={{ height: 12, display: "flex", borderRadius: 6, overflow: "hidden", gap: 2 }}>
        {data.map(d => d.v > 0 ? <div key={d.l} style={{ flex: d.v, background: `linear-gradient(180deg, ${d.c}, ${d.c}80)`, borderRadius: 4, boxShadow: `0 0 6px ${d.c}30` }} /> : null)}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10 }}>
        {data.map(d => <div key={d.l} style={{ display: "flex", alignItems: "center", gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: 2, background: d.c }} /><span style={{ fontSize: 8, color: "#6B7280" }}>{d.l}</span></div>)}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
//  MAIN
// ══════════════════════════════════════════════════════════════
export default function TestUIPage() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [models, setModels] = useState<string[]>([]);
  const [counts, setCounts] = useState({ critical: 0, high: 0, medium: 0, low: 0 });

  useEffect(() => {
    Promise.all([
      fetch("/api/tc/health").then(r => r.json()).catch(() => null),
      fetch("/api/ollama").then(r => r.json()).catch(() => ({ models: [] })),
      fetch("/api/tc/findings/counts").then(r => r.json()).catch(() => ({})),
    ]).then(([h, o, c]) => {
      setHealth(h); setModels((o?.models || []).map((m: any) => m.name));
      setCounts({ critical: c?.CRITICAL || 0, high: c?.HIGH || 0, medium: c?.MEDIUM || 0, low: c?.LOW || 0 });
    });
  }, []);

  const ok = health?.status === "ok" || health?.status === "healthy";
  const dbOk = health?.database === true;
  const aiOk = models.length > 0;
  const mlOk = health?.ml?.alive === true;
  const total = counts.critical + counts.high + counts.medium + counts.low;
  const score = ok ? 100 : 0;

  const svcs = [
    { l: "PostgreSQL", ok: dbOk, d: "PG16+AGE", a: -90 },
    { l: "Ollama", ok: aiOk, d: `${models.length} models`, a: -30 },
    { l: "ML", ok: mlOk, d: `${health?.ml?.data_days || 0}d`, a: 30 },
    { l: "Graph", ok: dbOk, d: "STIX", a: 90 },
    { l: "Telegram", ok, d: "HITL", a: 150 },
    { l: "Syslog", ok: true, d: "514", a: 210 },
  ];

  return (
    <div style={{ minHeight: "100vh", background: "#0f0f13", color: "#e8e4e0", fontFamily: "-apple-system, 'Inter', sans-serif", padding: "24px 32px", maxWidth: 1200, margin: "0 auto" }}>
      <div style={{ fontSize: 15, fontWeight: 800, letterSpacing: "0.12em", marginBottom: 4 }}>
        <span style={{ color: "#e8e4e0" }}>THREAT</span><span style={{ color: "#d03020" }}>CLAW</span>
        <span style={{ fontSize: 9, color: "#6B7280", marginLeft: 12, fontWeight: 600 }}>Test UI — Choisis tes tuiles preferees</span>
      </div>

      <SectionTitle>Score Securite — 4 variantes</SectionTitle>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 16 }}>
        <Score_A score={score} /><Score_B score={score} /><Score_C score={score} /><Score_D score={score} />
      </div>

      <SectionTitle>Pipeline — 4 variantes</SectionTitle>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Pipeline_A ok={ok} ai={aiOk} n={total} /><Pipeline_B ok={ok} ai={aiOk} n={total} />
        <Pipeline_C ok={ok} ai={aiOk} n={total} /><Pipeline_D ok={ok} ai={aiOk} n={total} />
      </div>

      <SectionTitle>Hub Services — 4 variantes</SectionTitle>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 16 }}>
        <Hub_A svcs={svcs} /><Hub_B svcs={svcs} /><Hub_C svcs={svcs} /><Hub_D svcs={svcs} />
      </div>

      <SectionTitle>Findings — 4 variantes</SectionTitle>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 16 }}>
        <Findings_A counts={counts} /><Findings_B counts={counts} /><Findings_C counts={counts} /><Findings_D counts={counts} />
      </div>
    </div>
  );
}
