"use client";

// Route: /exports/incident-response
// Thin wrapper around ExportsView scoped to the "incident-response"
// category. Lets the RSSI land on a page dedicated to breach / NIS2 /
// legal reports without seeing the other families.
import { ExportsView } from "../page";

export default function IncidentResponseReportsPage() {
  return <ExportsView category="incident-response" />;
}
