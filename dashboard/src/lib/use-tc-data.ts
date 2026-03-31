"use client";

import { useState, useEffect, useCallback } from "react";
import {
  fetchDashboardMetrics,
  fetchFindings,
  fetchAlerts,
  fetchFindingsCounts,
  fetchAlertsCounts,
  fetchHealth,
  type DashboardMetrics,
  type Finding,
  type Alert,
  type CountEntry,
  type HealthResponse,
} from "./tc-api";

// ── Generic fetch hook with auto-refresh ──

function useApiData<T>(
  fetcher: () => Promise<T>,
  fallback: T,
  refreshInterval = 30000
): { data: T; loading: boolean; error: string | null; refresh: () => void } {
  const [data, setData] = useState<T>(fallback);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    fetcher()
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [fetcher]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, refreshInterval);
    return () => clearInterval(interval);
  }, [refresh, refreshInterval]);

  return { data, loading, error, refresh };
}

// ── Typed hooks ──

export function useHealth() {
  return useApiData<HealthResponse>(
    fetchHealth,
    { status: "unknown", version: "0.0.0", database: false, llm: "unknown" },
    60000
  );
}

export function useMetrics() {
  return useApiData<DashboardMetrics>(
    fetchDashboardMetrics,
    {
      security_score: 0,
      findings_critical: 0,
      findings_high: 0,
      findings_medium: 0,
      findings_low: 0,
      alerts_total: 0,
      alerts_new: 0,
      cloud_score: 0,
      darkweb_leaks: 0,
    },
    15000
  );
}

export function useFindings(params?: {
  severity?: string;
  status?: string;
  limit?: number;
}) {
  const fetcher = useCallback(
    () => fetchFindings(params).then((r) => r.findings),
    [params]
  );
  return useApiData<Finding[]>(fetcher, [], 15000);
}

export function useFindingsCounts() {
  return useApiData<CountEntry[]>(fetchFindingsCounts, [], 15000);
}

export function useAlerts(params?: {
  level?: string;
  status?: string;
  limit?: number;
}) {
  const fetcher = useCallback(
    () => fetchAlerts(params).then((r) => r.alerts),
    [params]
  );
  return useApiData<Alert[]>(fetcher, [], 10000);
}

export function useAlertsCounts() {
  return useApiData<CountEntry[]>(fetchAlertsCounts, [], 15000);
}
