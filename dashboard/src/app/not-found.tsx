"use client";

import Link from "next/link";

export default function NotFound() {
  return (
    <div style={{
      position: "fixed",
      inset: 0,
      zIndex: 100,
      background: "var(--tc-bg, #0a0a0f)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      overflow: "hidden",
    }}>
      {/* Grid background */}
      <div style={{
        position: "absolute", inset: 0,
        backgroundImage:
          "linear-gradient(rgba(208,48,32,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(208,48,32,0.03) 1px, transparent 1px)",
        backgroundSize: "60px 60px",
        animation: "gridPulse 8s ease-in-out infinite",
      }} />

      {/* Red glow */}
      <div style={{
        position: "absolute",
        top: "30%", left: "50%",
        transform: "translate(-50%, -50%)",
        width: 600, height: 600,
        background: "radial-gradient(circle, rgba(208,48,32,0.08) 0%, transparent 70%)",
        pointerEvents: "none",
      }} />

      {/* Scanline */}
      <div style={{
        position: "absolute", top: 0, left: 0, right: 0, height: 2,
        background: "linear-gradient(90deg, transparent, rgba(208,48,32,0.3), transparent)",
        animation: "scanDown 8s linear infinite",
        pointerEvents: "none",
        zIndex: 10,
      }} />

      <div style={{ position: "relative", zIndex: 1, textAlign: "center", maxWidth: 560, padding: "0 24px" }}>

        {/* Logo */}
        <svg width={80} height={80} viewBox="0 0 200 200" fill="none" style={{
          margin: "0 auto 32px",
          display: "block",
          opacity: 0.6,
          filter: "drop-shadow(0 0 20px rgba(208,48,32,0.3))",
          animation: "logoPulse 4s ease-in-out infinite",
        }}>
          <path d="M160 70c-10-30-40-50-70-50S40 40 30 70c-5 15-5 30 0 45 8 25 30 45 55 55 5 2 10 3 15 3s10-1 15-3c25-10 47-30 55-55 5-15 5-30 0-45z" stroke="#d03020" strokeWidth={4} fill="none"/>
          <path d="M100 50c-20 0-38 12-45 30-4 10-4 22 0 32 6 18 22 32 40 40l5 2 5-2c18-8 34-22 40-40 4-10 4-22 0-32-7-18-25-30-45-30z" stroke="#d03020" strokeWidth={3} fill="rgba(208,48,32,0.05)"/>
          <circle cx={90} cy={85} r={4} fill="#d03020" opacity={0.8}/>
          <path d="M70 90h60" stroke="#d03020" strokeWidth={2} opacity={0.3}/>
          <path d="M75 100h50" stroke="#d03020" strokeWidth={1.5} opacity={0.2}/>
        </svg>

        {/* Error code */}
        <div style={{
          fontSize: 120, fontWeight: 800, lineHeight: 1, letterSpacing: -4,
          background: "linear-gradient(135deg, #d03020 0%, #ff6050 40%, #d03020 100%)",
          backgroundSize: "200% 200%",
          WebkitBackgroundClip: "text",
          WebkitTextFillColor: "transparent",
          backgroundClip: "text",
          animation: "gradientShift 6s ease infinite",
          marginBottom: 8,
        }}>
          404
        </div>

        <h1 style={{
          fontSize: 22, fontWeight: 600,
          color: "var(--tc-text, #e8e4e0)",
          marginBottom: 16, letterSpacing: -0.3,
        }}>
          Page introuvable
        </h1>

        <p style={{
          fontSize: 14, fontWeight: 300,
          color: "rgba(232,228,224,0.5)",
          lineHeight: 1.7, marginBottom: 32,
        }}>
          La ressource demand&eacute;e n&apos;existe pas sur ce serveur.
          Elle a peut-&ecirc;tre &eacute;t&eacute; d&eacute;plac&eacute;e ou supprim&eacute;e.
        </p>

        {/* Fix card */}
        <div style={{
          background: "rgba(18,18,26,0.7)",
          border: "1px solid rgba(208,48,32,0.15)",
          borderRadius: 12,
          padding: "20px 24px",
          textAlign: "left",
          backdropFilter: "blur(20px)",
          WebkitBackdropFilter: "blur(20px)",
          marginBottom: 32,
        }}>
          <div style={{
            fontSize: 11, fontWeight: 600, textTransform: "uppercase",
            letterSpacing: 1.5, color: "#d03020", marginBottom: 12,
          }}>
            Actions recommand&eacute;es
          </div>

          {[
            "V\u00e9rifiez l\u2019URL \u2014 une faute de frappe est vite arriv\u00e9e",
            "Acc\u00e9dez au dashboard depuis la page d\u2019accueil",
            "Les endpoints API sont sous /api/",
          ].map((text, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "flex-start", gap: 10,
              padding: "8px 0", fontSize: 13,
              color: "rgba(232,228,224,0.7)", lineHeight: 1.5,
              borderTop: i > 0 ? "1px solid rgba(255,255,255,0.04)" : "none",
            }}>
              <svg width={16} height={16} viewBox="0 0 24 24" fill="none"
                stroke="#d03020" strokeWidth={2} opacity={0.7}
                style={{ flexShrink: 0, marginTop: 2 }}>
                <polyline points="9 18 15 12 9 6"/>
              </svg>
              <span>{text}</span>
            </div>
          ))}
        </div>

        {/* Button */}
        <Link href="/" style={{
          display: "inline-flex", alignItems: "center", gap: 8,
          padding: "12px 28px",
          background: "rgba(208,48,32,0.12)",
          border: "1px solid rgba(208,48,32,0.25)",
          borderRadius: 8,
          color: "var(--tc-text, #e8e4e0)",
          fontSize: 13, fontWeight: 600,
          textDecoration: "none",
          transition: "all 0.2s ease",
          backdropFilter: "blur(10px)",
        }}>
          <svg width={16} height={16} viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
            <polyline points="9 22 9 12 15 12 15 22"/>
          </svg>
          Dashboard
        </Link>
      </div>

      {/* Status line */}
      <div style={{
        position: "fixed", bottom: 24, left: "50%", transform: "translateX(-50%)",
        display: "flex", alignItems: "center", gap: 8,
        fontSize: 11, color: "rgba(232,228,224,0.25)", letterSpacing: 0.5,
      }}>
        <span style={{
          width: 6, height: 6, borderRadius: "50%",
          background: "#d03020",
          animation: "dotBlink 2s ease-in-out infinite",
        }} />
        ThreatClaw Agent
      </div>

      <style>{`
        @keyframes gridPulse { 0%,100%{opacity:.5} 50%{opacity:1} }
        @keyframes logoPulse { 0%,100%{opacity:.5;filter:drop-shadow(0 0 20px rgba(208,48,32,.2))} 50%{opacity:.8;filter:drop-shadow(0 0 30px rgba(208,48,32,.4))} }
        @keyframes gradientShift { 0%,100%{background-position:0% 50%} 50%{background-position:100% 50%} }
        @keyframes scanDown { 0%{top:-2px} 100%{top:100vh} }
        @keyframes dotBlink { 0%,100%{opacity:.3} 50%{opacity:1} }
      `}</style>
    </div>
  );
}
