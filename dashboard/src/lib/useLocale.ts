"use client";

import { useState, useEffect } from "react";
import type { Locale } from "./i18n";

/**
 * Hook to get the current locale.
 * Reads from localStorage (set by Config > General > Language).
 * Defaults to "fr".
 */
export function useLocale(): Locale {
  const [locale, setLocale] = useState<Locale>("fr");

  useEffect(() => {
    // Read from localStorage (set by ConfigPage when language changes)
    const saved = localStorage.getItem("tc-language") as Locale | null;
    if (saved && (saved === "fr" || saved === "en")) {
      setLocale(saved);
    }

    // Listen for changes (when user switches language in Config)
    const handler = () => {
      const lang = localStorage.getItem("tc-language") as Locale | null;
      if (lang) setLocale(lang);
    };
    window.addEventListener("storage", handler);
    // Also listen for custom event (same-tab changes)
    window.addEventListener("tc-locale-change", handler);
    return () => {
      window.removeEventListener("storage", handler);
      window.removeEventListener("tc-locale-change", handler);
    };
  }, []);

  return locale;
}
