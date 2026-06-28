// Shared relative-time formatter (FR/EN). Factored out of app/page.tsx so the
// inventory and other pages render "il y a 2 min" / "2 min ago" consistently.
import type { Locale } from "@/lib/i18n";

/** Format an RFC3339 timestamp as a short relative string, localised. */
export function formatRelative(iso: string | null | undefined, locale: Locale, now?: Date): string {
  if (!iso) return "—";
  const ref = now ?? new Date();
  const d = new Date(iso);
  const diff = Math.max(0, ref.getTime() - d.getTime()) / 1000;
  const fr = locale === "fr";
  if (diff < 60) return fr ? `il y a ${Math.round(diff)} s` : `${Math.round(diff)}s ago`;
  if (diff < 3600) return fr ? `il y a ${Math.round(diff / 60)} min` : `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return fr ? `il y a ${Math.round(diff / 3600)} h` : `${Math.round(diff / 3600)}h ago`;
  return fr ? `il y a ${Math.round(diff / 86400)} j` : `${Math.round(diff / 86400)}d ago`;
}
