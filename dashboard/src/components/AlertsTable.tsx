"use client";

import React, { useState } from "react";
import { ChevronLeft, ChevronRight, Clock, User } from "lucide-react";
import type { Alert } from "@/lib/types";

interface AlertsTableProps {
  alerts: Alert[];
  total: number;
  page: number;
  pageSize: number;
  onPageChange?: (page: number) => void;
  compact?: boolean;
}

const severityBadge: Record<string, string> = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
  info: "badge-info",
};

const statusStyles: Record<string, { label: string; color: string }> = {
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
  const date = new Date(ts);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);

  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function AlertsTable({
  alerts,
  total,
  page,
  pageSize,
  onPageChange,
  compact = false,
}: AlertsTableProps) {
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const totalPages = Math.ceil(total / pageSize);

  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-gray-700/50">
              <th className="pb-3 pr-4 text-xs font-medium uppercase tracking-wider text-gray-500">
                Severity
              </th>
              <th className="pb-3 pr-4 text-xs font-medium uppercase tracking-wider text-gray-500">
                Alert
              </th>
              {!compact && (
                <th className="pb-3 pr-4 text-xs font-medium uppercase tracking-wider text-gray-500">
                  Source
                </th>
              )}
              <th className="pb-3 pr-4 text-xs font-medium uppercase tracking-wider text-gray-500">
                Status
              </th>
              <th className="pb-3 text-xs font-medium uppercase tracking-wider text-gray-500">
                Time
              </th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => {
              const status = statusStyles[alert.status] ?? statusStyles.new;

              return (
                <tr
                  key={alert.id}
                  className="table-row cursor-pointer"
                  onClick={() => setSelectedAlert(alert)}
                >
                  <td className="py-3 pr-4">
                    <span
                      className={
                        severityBadge[alert.severity] ?? "badge-info"
                      }
                    >
                      {alert.severity.charAt(0).toUpperCase() +
                        alert.severity.slice(1)}
                    </span>
                  </td>
                  <td className="py-3 pr-4">
                    <div>
                      <p className="font-medium text-gray-200">
                        {alert.title}
                      </p>
                      {!compact && (
                        <p className="mt-0.5 text-xs text-gray-500 truncate max-w-md">
                          {alert.description}
                        </p>
                      )}
                    </div>
                  </td>
                  {!compact && (
                    <td className="py-3 pr-4 text-gray-400">{alert.source}</td>
                  )}
                  <td className="py-3 pr-4">
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs font-medium ${status.color}`}
                    >
                      {status.label}
                    </span>
                  </td>
                  <td className="py-3 text-gray-400">
                    <div className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      <span className="text-xs">
                        {formatTimestamp(alert.timestamp)}
                      </span>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-4 flex items-center justify-between border-t border-gray-700/30 pt-4">
          <p className="text-sm text-gray-500">
            Showing {(page - 1) * pageSize + 1} to{" "}
            {Math.min(page * pageSize, total)} of {total} alerts
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onPageChange?.(page - 1)}
              disabled={page <= 1}
              className="rounded-lg p-1.5 text-gray-400 transition-colors hover:bg-white/5 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
              <button
                key={p}
                onClick={() => onPageChange?.(p)}
                className={`h-8 w-8 rounded-lg text-sm font-medium transition-colors ${
                  p === page
                    ? "bg-accent text-white"
                    : "text-gray-400 hover:bg-white/5 hover:text-white"
                }`}
              >
                {p}
              </button>
            ))}
            <button
              onClick={() => onPageChange?.(page + 1)}
              disabled={page >= totalPages}
              className="rounded-lg p-1.5 text-gray-400 transition-colors hover:bg-white/5 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => setSelectedAlert(null)}
        >
          <div
            className="mx-4 w-full max-w-2xl rounded-xl border border-gray-700/30 bg-secondary p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span
                    className={
                      severityBadge[selectedAlert.severity] ?? "badge-info"
                    }
                  >
                    {selectedAlert.severity.toUpperCase()}
                  </span>
                  <span className="text-xs text-gray-500">
                    {selectedAlert.id}
                  </span>
                </div>
                <h3 className="text-lg font-semibold text-white">
                  {selectedAlert.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="rounded-lg p-1 text-gray-400 hover:bg-white/5 hover:text-white"
              >
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <p className="mb-4 text-sm text-gray-300">
              {selectedAlert.description}
            </p>

            <div className="mb-4 grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs font-medium uppercase text-gray-500">
                  Source
                </p>
                <p className="mt-1 text-sm text-gray-300">
                  {selectedAlert.source}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium uppercase text-gray-500">
                  Status
                </p>
                <p className="mt-1">
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                      (statusStyles[selectedAlert.status] ?? statusStyles.new)
                        .color
                    }`}
                  >
                    {
                      (statusStyles[selectedAlert.status] ?? statusStyles.new)
                        .label
                    }
                  </span>
                </p>
              </div>
              <div>
                <p className="text-xs font-medium uppercase text-gray-500">
                  MITRE Tactic
                </p>
                <p className="mt-1 text-sm text-gray-300">
                  {selectedAlert.mitreTactic ?? "N/A"}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium uppercase text-gray-500">
                  MITRE Technique
                </p>
                <p className="mt-1 text-sm font-mono text-gray-300">
                  {selectedAlert.mitretechnique ?? "N/A"}
                </p>
              </div>
              {selectedAlert.assignee && (
                <div>
                  <p className="text-xs font-medium uppercase text-gray-500">
                    Assignee
                  </p>
                  <p className="mt-1 flex items-center gap-1 text-sm text-gray-300">
                    <User className="h-3 w-3" />
                    {selectedAlert.assignee}
                  </p>
                </div>
              )}
              {selectedAlert.correlationGroup && (
                <div>
                  <p className="text-xs font-medium uppercase text-gray-500">
                    Correlation Group
                  </p>
                  <p className="mt-1 text-sm font-mono text-accent">
                    {selectedAlert.correlationGroup}
                  </p>
                </div>
              )}
            </div>

            {selectedAlert.indicators.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-medium uppercase text-gray-500">
                  Indicators
                </p>
                <div className="flex flex-wrap gap-2">
                  {selectedAlert.indicators.map((indicator, i) => (
                    <span
                      key={i}
                      className="rounded-md bg-primary/50 px-2 py-1 text-xs font-mono text-gray-300"
                    >
                      {indicator}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
