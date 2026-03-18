"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Bell,
  Filter,
  Search,
  X,
  Clock,
  User,
  GitBranch,
  RefreshCw,
} from "lucide-react";
import { fetchAlerts } from "@/lib/api";
import type { Alert, AlertsResponse, AlertFilters } from "@/lib/types";
import AlertsTable from "@/components/AlertsTable";

const severityOptions = ["all", "critical", "high", "medium", "low", "info"];
const statusOptions = [
  "all",
  "new",
  "investigating",
  "resolved",
  "false_positive",
];
const sourceOptions = [
  "all",
  "CrowdStrike",
  "Microsoft Defender",
  "Darktrace",
  "AWS CloudTrail",
  "Proofpoint",
  "Falco",
  "Infoblox",
  "CertStream",
  "Azure AD",
  "Okta",
  "WAF",
];

const severityTimelineColor: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-gray-500",
};

const statusLabel: Record<string, { label: string; color: string }> = {
  new: { label: "New", color: "bg-accent/20 text-accent" },
  investigating: {
    label: "Investigating",
    color: "bg-yellow-500/20 text-yellow-400",
  },
  resolved: { label: "Resolved", color: "bg-green-500/20 text-green-400" },
  false_positive: {
    label: "False Positive",
    color: "bg-gray-500/20 text-gray-400",
  },
};

function formatTimestamp(ts: string): string {
  return new Date(ts).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function AlertsPage() {
  const [data, setData] = useState<AlertsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState<AlertFilters>({
    page: 1,
    pageSize: 10,
  });
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [view, setView] = useState<"table" | "timeline">("table");

  const loadAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const cleanFilters: AlertFilters = { ...filters };
      if (cleanFilters.severity === "all") delete cleanFilters.severity;
      if (cleanFilters.source === "all") delete cleanFilters.source;
      if (cleanFilters.status === "all") delete cleanFilters.status;
      const result = await fetchAlerts(cleanFilters);
      setData(result);
    } catch (err) {
      console.error("Failed to load alerts:", err);
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  // Group alerts by correlation group
  const correlationGroups = data
    ? data.alerts.reduce<Record<string, Alert[]>>((acc, alert) => {
        if (alert.correlationGroup) {
          if (!acc[alert.correlationGroup]) {
            acc[alert.correlationGroup] = [];
          }
          acc[alert.correlationGroup].push(alert);
        }
        return acc;
      }, {})
    : {};

  const activeCorrelationGroups = Object.entries(correlationGroups).filter(
    ([, alerts]) => alerts.length > 1
  );

  return (
    <div>
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Bell className="h-7 w-7 text-accent" />
            <h1 className="text-2xl font-bold text-white">SOC Alerts</h1>
          </div>
          <p className="text-sm text-gray-400">
            Security Operations Center alert management and investigation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => loadAlerts()}
            className="btn-secondary"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`btn-secondary ${showFilters ? "border-accent text-accent" : ""}`}
          >
            <Filter className="h-4 w-4" />
            Filters
          </button>
        </div>
      </div>

      {/* Alert Stats */}
      <div className="mb-6 grid grid-cols-4 gap-4">
        {(["new", "investigating", "resolved", "false_positive"] as const).map(
          (status) => {
            const count =
              data?.alerts.filter((a) => a.status === status).length ?? 0;
            const info = statusLabel[status];
            return (
              <div
                key={status}
                className="card-hover cursor-pointer"
                onClick={() =>
                  setFilters((f) => ({
                    ...f,
                    status: f.status === status ? undefined : status,
                    page: 1,
                  }))
                }
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-400">{info.label}</span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs font-medium ${info.color}`}
                  >
                    {count}
                  </span>
                </div>
              </div>
            );
          }
        )}
      </div>

      {/* Filters Panel */}
      {showFilters && (
        <div className="mb-6 card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-white">Filters</h3>
            <button
              onClick={() => {
                setFilters({ page: 1, pageSize: 10 });
                setShowFilters(false);
              }}
              className="text-xs text-gray-400 hover:text-white transition-colors"
            >
              Clear all
            </button>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-gray-400">
                Severity
              </label>
              <select
                value={filters.severity ?? "all"}
                onChange={(e) =>
                  setFilters((f) => ({
                    ...f,
                    severity: e.target.value,
                    page: 1,
                  }))
                }
                className="input"
              >
                {severityOptions.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt.charAt(0).toUpperCase() + opt.slice(1)}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-gray-400">
                Source
              </label>
              <select
                value={filters.source ?? "all"}
                onChange={(e) =>
                  setFilters((f) => ({
                    ...f,
                    source: e.target.value,
                    page: 1,
                  }))
                }
                className="input"
              >
                {sourceOptions.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt === "all" ? "All Sources" : opt}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-gray-400">
                Status
              </label>
              <select
                value={filters.status ?? "all"}
                onChange={(e) =>
                  setFilters((f) => ({
                    ...f,
                    status: e.target.value,
                    page: 1,
                  }))
                }
                className="input"
              >
                {statusOptions.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt === "all"
                      ? "All Statuses"
                      : opt.charAt(0).toUpperCase() +
                        opt.slice(1).replace("_", " ")}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Correlation Groups */}
      {activeCorrelationGroups.length > 0 && (
        <div className="mb-6">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
            <GitBranch className="h-4 w-4 text-accent" />
            Correlated Alert Groups
          </h3>
          <div className="grid grid-cols-2 gap-4">
            {activeCorrelationGroups.map(([groupId, groupAlerts]) => (
              <div key={groupId} className="card-hover">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-mono text-accent">
                    {groupId}
                  </span>
                  <span className="text-xs text-gray-500">
                    {groupAlerts.length} alerts
                  </span>
                </div>
                <div className="space-y-1">
                  {groupAlerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="flex items-center gap-2 text-xs"
                    >
                      <div
                        className={`h-2 w-2 rounded-full ${
                          severityTimelineColor[alert.severity] ?? "bg-gray-500"
                        }`}
                      />
                      <span className="text-gray-400 truncate">
                        {alert.title}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* View Toggle */}
      <div className="mb-4 flex items-center gap-2">
        <button
          onClick={() => setView("table")}
          className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
            view === "table"
              ? "bg-accent/20 text-accent"
              : "text-gray-400 hover:text-white"
          }`}
        >
          Table View
        </button>
        <button
          onClick={() => setView("timeline")}
          className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
            view === "timeline"
              ? "bg-accent/20 text-accent"
              : "text-gray-400 hover:text-white"
          }`}
        >
          Timeline View
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex h-40 items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-gray-700 border-t-accent" />
        </div>
      ) : view === "table" ? (
        <div className="card">
          {data && (
            <AlertsTable
              alerts={data.alerts}
              total={data.total}
              page={data.page}
              pageSize={data.pageSize}
              onPageChange={(page) => setFilters((f) => ({ ...f, page }))}
            />
          )}
        </div>
      ) : (
        /* Timeline View */
        <div className="card">
          <div className="relative">
            <div className="absolute left-4 top-0 h-full w-px bg-gray-700/50" />
            <div className="space-y-6">
              {data?.alerts.map((alert) => {
                const stInfo = statusLabel[alert.status] ?? statusLabel.new;
                return (
                  <div key={alert.id} className="relative flex gap-4 pl-10">
                    <div
                      className={`absolute left-2.5 top-1 h-3 w-3 rounded-full ring-4 ring-primary ${
                        severityTimelineColor[alert.severity] ?? "bg-gray-500"
                      }`}
                    />
                    <div className="flex-1 rounded-lg bg-primary/40 p-4 transition-colors hover:bg-primary/60">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs font-mono text-gray-500">
                              {alert.id}
                            </span>
                            <span
                              className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${stInfo.color}`}
                            >
                              {stInfo.label}
                            </span>
                          </div>
                          <h4 className="text-sm font-medium text-white">
                            {alert.title}
                          </h4>
                        </div>
                        <div className="flex items-center gap-1 text-xs text-gray-500">
                          <Clock className="h-3 w-3" />
                          {formatTimestamp(alert.timestamp)}
                        </div>
                      </div>
                      <p className="text-xs text-gray-400 mb-2">
                        {alert.description}
                      </p>
                      <div className="flex items-center gap-3 text-xs text-gray-500">
                        <span>Source: {alert.source}</span>
                        {alert.mitreTactic && (
                          <span>
                            MITRE: {alert.mitreTactic}
                          </span>
                        )}
                        {alert.assignee && (
                          <span className="flex items-center gap-1">
                            <User className="h-3 w-3" />
                            {alert.assignee}
                          </span>
                        )}
                      </div>
                      {alert.indicators.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {alert.indicators.map((ind, i) => (
                            <span
                              key={i}
                              className="rounded bg-gray-700/50 px-1.5 py-0.5 text-[10px] font-mono text-gray-400"
                            >
                              {ind}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
