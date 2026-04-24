"use client";

// Route: /exports/threat-intel
// Real-time snapshots for SOC-to-SOC sharing, feeding firewall / EDR.
import { ExportsView } from "../page";

export default function ThreatIntelReportsPage() {
  return <ExportsView category="threat-intel" />;
}
