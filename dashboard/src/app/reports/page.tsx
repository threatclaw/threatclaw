"use client";

import React, { useEffect, useState } from "react";
import {
  FileText,
  Download,
  Plus,
  FileCheck2,
  Loader2,
  AlertCircle,
  Calendar,
  HardDrive,
  ExternalLink,
} from "lucide-react";
import { fetchReports, generateReport } from "@/lib/api";
import type { Report, ReportsResponse } from "@/lib/types";

const reportTypeLabels: Record<Report["type"], { label: string; color: string }> = {
  security_posture: {
    label: "Security Posture",
    color: "bg-blue-500/20 text-blue-400",
  },
  nis2_compliance: {
    label: "NIS2 Compliance",
    color: "bg-green-500/20 text-green-400",
  },
  incident_summary: {
    label: "Incident Summary",
    color: "bg-orange-500/20 text-orange-400",
  },
  executive_brief: {
    label: "Executive Brief",
    color: "bg-purple-500/20 text-purple-400",
  },
};

const statusConfig: Record<
  Report["status"],
  { icon: React.ElementType; label: string; color: string }
> = {
  ready: {
    icon: FileCheck2,
    label: "Ready",
    color: "text-green-400",
  },
  generating: {
    icon: Loader2,
    label: "Generating...",
    color: "text-yellow-400",
  },
  failed: {
    icon: AlertCircle,
    label: "Failed",
    color: "text-red-400",
  },
};

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function ReportsPage() {
  const [data, setData] = useState<ReportsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [selectedType, setSelectedType] = useState<Report["type"]>("security_posture");

  useEffect(() => {
    fetchReports()
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  async function handleGenerate() {
    setGenerating(true);
    try {
      const result = await generateReport(selectedType);
      // Add the generating report to the list
      if (data) {
        const newReport: Report = {
          id: result.reportId,
          title: `${reportTypeLabels[selectedType].label} - ${new Date().toLocaleDateString("en-US", { month: "long", year: "numeric" })}`,
          type: selectedType,
          status: "generating",
          createdAt: new Date().toISOString(),
          format: "pdf",
          size: "",
          downloadUrl: "",
        };
        setData({ reports: [newReport, ...data.reports] });
      }
      setShowGenerateModal(false);
    } catch (err) {
      console.error("Failed to generate report:", err);
    } finally {
      setGenerating(false);
    }
  }

  if (loading) {
    return (
      <div className="flex h-[80vh] items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-gray-700 border-t-accent" />
          <p className="text-sm text-gray-400">Loading reports...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <FileText className="h-7 w-7 text-accent" />
            <h1 className="text-2xl font-bold text-white">Reports</h1>
          </div>
          <p className="text-sm text-gray-400">
            Generate and download security assessment reports
          </p>
        </div>
        <button
          onClick={() => setShowGenerateModal(true)}
          className="btn-primary"
        >
          <Plus className="h-4 w-4" />
          Generate Report
        </button>
      </div>

      {/* Report Type Quick Stats */}
      <div className="mb-6 grid grid-cols-4 gap-4">
        {(
          Object.entries(reportTypeLabels) as [
            Report["type"],
            { label: string; color: string },
          ][]
        ).map(([type, info]) => {
          const count =
            data?.reports.filter((r) => r.type === type).length ?? 0;
          return (
            <div key={type} className="card-hover">
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
        })}
      </div>

      {/* Reports List */}
      <div className="card">
        <h2 className="mb-4 text-lg font-semibold text-white">
          Report History
        </h2>
        <div className="space-y-3">
          {data?.reports.map((report) => {
            const typeInfo = reportTypeLabels[report.type];
            const status = statusConfig[report.status];
            const StatusIcon = status.icon;

            return (
              <div
                key={report.id}
                className="flex items-center gap-4 rounded-lg border border-gray-700/20 bg-primary/30 p-4 transition-colors hover:bg-primary/50"
              >
                {/* Icon */}
                <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-secondary">
                  <FileText className="h-5 w-5 text-gray-400" />
                </div>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-sm font-medium text-white truncate">
                      {report.title}
                    </h3>
                    <span
                      className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${typeInfo.color}`}
                    >
                      {typeInfo.label}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-gray-500">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" />
                      {formatDate(report.createdAt)}
                    </span>
                    {report.size && (
                      <span className="flex items-center gap-1">
                        <HardDrive className="h-3 w-3" />
                        {report.size}
                      </span>
                    )}
                    <span className="uppercase font-mono">
                      {report.format}
                    </span>
                  </div>
                </div>

                {/* Status */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <StatusIcon
                    className={`h-4 w-4 ${status.color} ${
                      report.status === "generating" ? "animate-spin" : ""
                    }`}
                  />
                  <span className={`text-xs font-medium ${status.color}`}>
                    {status.label}
                  </span>
                </div>

                {/* Download */}
                {report.status === "ready" && (
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <a
                      href={report.downloadUrl}
                      className="btn-secondary text-xs"
                      title={`Download ${report.format.toUpperCase()}`}
                    >
                      <Download className="h-3.5 w-3.5" />
                      {report.format.toUpperCase()}
                    </a>
                  </div>
                )}
              </div>
            );
          })}

          {(!data || data.reports.length === 0) && (
            <div className="flex flex-col items-center justify-center py-12">
              <FileText className="h-12 w-12 text-gray-600 mb-3" />
              <p className="text-sm text-gray-400">No reports generated yet</p>
              <button
                onClick={() => setShowGenerateModal(true)}
                className="mt-4 btn-primary"
              >
                <Plus className="h-4 w-4" />
                Generate your first report
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => setShowGenerateModal(false)}
        >
          <div
            className="mx-4 w-full max-w-md rounded-xl border border-gray-700/30 bg-secondary p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-white">
                Generate New Report
              </h3>
              <button
                onClick={() => setShowGenerateModal(false)}
                className="rounded-lg p-1 text-gray-400 hover:bg-white/5 hover:text-white"
              >
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="mb-6">
              <label className="mb-2 block text-sm font-medium text-gray-300">
                Report Type
              </label>
              <div className="space-y-2">
                {(
                  Object.entries(reportTypeLabels) as [
                    Report["type"],
                    { label: string; color: string },
                  ][]
                ).map(([type, info]) => (
                  <label
                    key={type}
                    className={`flex cursor-pointer items-center gap-3 rounded-lg border p-3 transition-colors ${
                      selectedType === type
                        ? "border-accent bg-accent/5"
                        : "border-gray-700/30 hover:border-gray-600"
                    }`}
                  >
                    <input
                      type="radio"
                      name="reportType"
                      value={type}
                      checked={selectedType === type}
                      onChange={() => setSelectedType(type)}
                      className="sr-only"
                    />
                    <div
                      className={`h-4 w-4 rounded-full border-2 ${
                        selectedType === type
                          ? "border-accent bg-accent"
                          : "border-gray-600"
                      }`}
                    >
                      {selectedType === type && (
                        <div className="flex h-full items-center justify-center">
                          <div className="h-1.5 w-1.5 rounded-full bg-white" />
                        </div>
                      )}
                    </div>
                    <span className="text-sm text-gray-200">{info.label}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowGenerateModal(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerate}
                disabled={generating}
                className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {generating ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Plus className="h-4 w-4" />
                    Generate
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
