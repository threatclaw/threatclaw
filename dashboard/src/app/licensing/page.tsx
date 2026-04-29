"use client";

// Legacy URL — the licensing page used to live here under the
// "Action Pack" model. The pricing pivot 2026-04-28 fused it with the
// /setup?tab=about content into a single canonical /license page.
// Permanent client-side redirect so any bookmarked link, email or in-
// app reference still lands on the right place.

import { useEffect } from "react";

export default function LegacyLicensingRedirect() {
  useEffect(() => {
    window.location.replace("/license");
  }, []);
  return null;
}
