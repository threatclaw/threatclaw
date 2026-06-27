"use client";

import React, { useState } from "react";
import { Loader2, ShieldAlert } from "lucide-react";
import { t as tr, interpolate, type Locale } from "@/lib/i18n";

/**
 * On-demand CVE scan button. Calls POST /api/tc/enrichment/scan, optionally
 * scoped to one asset (?asset=<id>).
 *
 * - With `assetId`: scans that asset synchronously (~a couple of seconds) and
 *   reports how many vulnerable packages / CVEs were found. This is what lets a
 *   freshly-onboarded host surface its CVEs on demand instead of waiting for the
 *   daily scan.
 * - Without `assetId`: kicks off a fleet-wide scan in the background.
 *
 * `variant="card"` renders a framed block with an explanatory hint (asset page);
 * `variant="inline"` renders a bare button (toolbars).
 */
export function CVEScanButton({
  assetId,
  locale,
  variant = "inline",
  onDone,
}: {
  assetId?: string;
  locale: Locale;
  variant?: "inline" | "card";
  onDone?: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [isError, setIsError] = useState(false);

  const scan = async () => {
    setBusy(true);
    setMsg(null);
    setIsError(false);
    try {
      const url = assetId
        ? `/api/tc/enrichment/scan?asset=${encodeURIComponent(assetId)}`
        : `/api/tc/enrichment/scan`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false || data.error) {
        setIsError(true);
        setMsg(data.error || tr("cveScan_error", locale));
      } else if (data.status === "started") {
        setMsg(tr("cveScan_fleetStarted", locale));
        onDone?.();
      } else if (data.software_checked === 0) {
        setMsg(tr("cveScan_noSoftware", locale));
      } else {
        setMsg(
          interpolate(tr("cveScan_done", locale), {
            findings: data.findings_created ?? 0,
            cves: data.cves_found ?? 0,
          }),
        );
        // Findings landed in the DB — let the parent refresh its view.
        onDone?.();
      }
    } catch (e) {
      setIsError(true);
      setMsg(e instanceof Error ? e.message : tr("cveScan_error", locale));
    }
    setBusy(false);
  };

  const button = (
    <button
      onClick={scan}
      disabled={busy}
      style={{
        padding: "6px 12px",
        fontSize: 11,
        fontWeight: 600,
        fontFamily: "inherit",
        borderRadius: "var(--tc-radius-sm)",
        background: "var(--tc-input)",
        border: "1px solid var(--tc-border)",
        color: "var(--tc-text-sec)",
        cursor: busy ? "wait" : "pointer",
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        opacity: busy ? 0.7 : 1,
        transition: "all 100ms",
      }}
    >
      {busy ? (
        <Loader2 size={12} className="animate-spin" />
      ) : (
        <ShieldAlert size={12} />
      )}
      {busy
        ? tr("cveScan_scanning", locale)
        : assetId
          ? tr("cveScan_button", locale)
          : tr("cveScan_fleetButton", locale)}
    </button>
  );

  const message = msg ? (
    <span
      style={{
        fontSize: 11,
        fontStyle: "italic",
        color: isError ? "var(--tc-red)" : "var(--tc-green)",
      }}
    >
      {msg}
    </span>
  ) : null;

  if (variant === "card") {
    return (
      <div
        style={{
          padding: "10px 14px",
          marginBottom: 14,
          background: "rgba(208,48,32,0.04)",
          border: "1px solid rgba(208,48,32,0.15)",
          borderRadius: "var(--tc-radius-sm)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <span style={{ fontSize: 11, color: "var(--tc-text-sec)" }}>
            {tr("cveScan_assetHint", locale)}
          </span>
          {button}
        </div>
        {message && <div style={{ marginTop: 8 }}>{message}</div>}
      </div>
    );
  }

  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
      {button}
      {message}
    </span>
  );
}
