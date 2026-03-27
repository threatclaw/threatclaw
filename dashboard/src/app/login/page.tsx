"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

export default function LoginPage() {
  const router = useRouter();
  const locale = useLocale();
  const [mode, setMode] = useState<"loading" | "setup" | "login">("loading");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Check if auth is configured
    fetch("/api/auth/status")
      .then(r => r.json())
      .then(d => {
        if (d.requires_setup) {
          setMode("setup");
        } else {
          // Check if already logged in
          fetch("/api/auth/me")
            .then(r => r.json())
            .then(me => {
              if (me.authenticated) {
                window.location.href = "/";
              } else {
                setMode("login");
              }
            })
            .catch(() => setMode("login"));
        }
      })
      .catch(() => setMode("login"));
  }, [router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (mode === "setup") {
        const res = await fetch("/api/auth/setup", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password, displayName: displayName || email.split("@")[0] }),
        });
        const data = await res.json();
        if (!data.ok) {
          setError(data.error || "Erreur lors de la creation");
          setLoading(false);
          return;
        }
        // Auto-login after setup
      }

      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (data.ok) {
        window.location.href = "/";
      } else {
        setError(data.error || "Identifiants incorrects");
      }
    } catch (err: any) {
      setError(err.message || "Erreur reseau");
    }
    setLoading(false);
  };

  if (mode === "loading") {
    return (
      <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--tc-bg, #0a0a0f)" }}>
        <div style={{ width: "20px", height: "20px", border: "2px solid rgba(255,255,255,0.1)", borderTopColor: "#d03020", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
      </div>
    );
  }

  return (
    <div style={{
      minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center",
      background: "#0a0a0f",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    }}>
      <div style={{
        width: "100%", maxWidth: "380px", padding: "40px",
        background: "rgba(20,20,28,0.95)",
        border: "1px solid rgba(255,255,255,0.06)",
        borderRadius: "16px",
        boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
      }}>
        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: "32px" }}>
          <img src="/logo.png" alt="ThreatClaw" width={48} height={48} style={{ borderRadius: "10px", marginBottom: "12px" }} />
          <div style={{ fontSize: "28px", fontWeight: 900, color: "#d03020", letterSpacing: "-0.5px" }}>
            ThreatClaw
          </div>
          <div style={{ fontSize: "11px", color: "rgba(255,255,255,0.35)", marginTop: "4px", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            {mode === "setup" ? tr("initialSetup", locale) : tr("login", locale)}
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          {mode === "setup" && (
            <div style={{ marginBottom: "16px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "rgba(255,255,255,0.5)", display: "block", marginBottom: "6px" }}>
                {tr("name", locale)}
              </label>
              <input
                type="text" value={displayName} onChange={e => setDisplayName(e.target.value)}
                placeholder="Administrateur"
                style={{
                  width: "100%", padding: "12px 14px", fontSize: "13px",
                  background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: "8px", color: "#fff", outline: "none",
                  transition: "border-color 0.2s",
                }}
                onFocus={e => e.target.style.borderColor = "rgba(208,48,32,0.4)"}
                onBlur={e => e.target.style.borderColor = "rgba(255,255,255,0.08)"}
              />
            </div>
          )}

          <div style={{ marginBottom: "16px" }}>
            <label style={{ fontSize: "11px", fontWeight: 600, color: "rgba(255,255,255,0.5)", display: "block", marginBottom: "6px" }}>
              {tr("email", locale)}
            </label>
            <input
              type="email" value={email} onChange={e => setEmail(e.target.value)}
              placeholder="admin@company.com" required autoFocus
              style={{
                width: "100%", padding: "12px 14px", fontSize: "13px",
                background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: "8px", color: "#fff", outline: "none",
                transition: "border-color 0.2s",
              }}
              onFocus={e => e.target.style.borderColor = "rgba(208,48,32,0.4)"}
              onBlur={e => e.target.style.borderColor = "rgba(255,255,255,0.08)"}
            />
          </div>

          <div style={{ marginBottom: "24px" }}>
            <label style={{ fontSize: "11px", fontWeight: 600, color: "rgba(255,255,255,0.5)", display: "block", marginBottom: "6px" }}>
              {tr("password", locale)}
            </label>
            <input
              type="password" value={password} onChange={e => setPassword(e.target.value)}
              placeholder={mode === "setup" ? tr("minPassword", locale) : "••••••••"} required
              minLength={mode === "setup" ? 8 : undefined}
              style={{
                width: "100%", padding: "12px 14px", fontSize: "13px",
                background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: "8px", color: "#fff", outline: "none",
                transition: "border-color 0.2s",
              }}
              onFocus={e => e.target.style.borderColor = "rgba(208,48,32,0.4)"}
              onBlur={e => e.target.style.borderColor = "rgba(255,255,255,0.08)"}
            />
          </div>

          {error && (
            <div style={{
              padding: "10px 14px", marginBottom: "16px", borderRadius: "8px",
              background: "rgba(208,48,32,0.1)", border: "1px solid rgba(208,48,32,0.2)",
              color: "#d03020", fontSize: "12px",
            }}>
              {error}
            </div>
          )}

          <button type="submit" disabled={loading} style={{
            width: "100%", padding: "12px", fontSize: "13px", fontWeight: 700,
            background: loading ? "rgba(208,48,32,0.3)" : "#d03020",
            color: "#fff", border: "none", borderRadius: "8px", cursor: loading ? "default" : "pointer",
            transition: "background 0.2s",
            fontFamily: "inherit",
          }}>
            {loading ? "..." : mode === "setup" ? tr("createAdmin", locale) : tr("signIn", locale)}
          </button>
        </form>

        {mode === "setup" && (
          <p style={{ fontSize: "10px", color: "rgba(255,255,255,0.25)", textAlign: "center", marginTop: "16px", lineHeight: 1.5 }}>
            {tr("firstRunHint", locale)}
            <br />{tr("fullAccessHint", locale)}
          </p>
        )}
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
