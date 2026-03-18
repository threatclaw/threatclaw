"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldCheck,
  AlertCircle,
  CheckCircle2,
  Clock,
  ArrowUpDown,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { fetchNIS2Compliance } from "@/lib/api";
import type { NIS2Compliance, NIS2Article, NIS2Gap } from "@/lib/types";

const maturityLevels = [
  { key: "initial", label: "Initial", value: 1, color: "bg-red-500" },
  { key: "developing", label: "Developing", value: 2, color: "bg-orange-500" },
  { key: "defined", label: "Defined", value: 3, color: "bg-yellow-500" },
  { key: "managed", label: "Managed", value: 4, color: "bg-blue-500" },
  { key: "optimized", label: "Optimized", value: 5, color: "bg-green-500" },
];

function getScoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

function getScoreBarColor(score: number): string {
  if (score >= 80) return "bg-green-500";
  if (score >= 60) return "bg-yellow-500";
  if (score >= 40) return "bg-orange-500";
  return "bg-red-500";
}

const priorityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const priorityBadge: Record<string, string> = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
};

const statusIcon: Record<string, React.ElementType> = {
  open: AlertCircle,
  in_progress: Clock,
  resolved: CheckCircle2,
};

type SortField = "priority" | "status" | "dueDate";
type SortDirection = "asc" | "desc";

export default function CompliancePage() {
  const [data, setData] = useState<NIS2Compliance | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedArticle, setExpandedArticle] = useState<string | null>(null);
  const [sortField, setSortField] = useState<SortField>("priority");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");

  useEffect(() => {
    fetchNIS2Compliance()
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex h-[80vh] items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-gray-700 border-t-accent" />
          <p className="text-sm text-gray-400">Loading compliance data...</p>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const allGaps: (NIS2Gap & { articleName: string })[] = data.articles.flatMap(
    (article) =>
      article.gaps.map((gap) => ({ ...gap, articleName: article.name }))
  );

  const sortedGaps = [...allGaps].sort((a, b) => {
    const dir = sortDirection === "asc" ? 1 : -1;
    switch (sortField) {
      case "priority":
        return (
          ((priorityOrder[a.priority] ?? 3) -
            (priorityOrder[b.priority] ?? 3)) *
          dir
        );
      case "status": {
        const statusOrder: Record<string, number> = {
          open: 0,
          in_progress: 1,
          resolved: 2,
        };
        return (
          ((statusOrder[a.status] ?? 2) - (statusOrder[b.status] ?? 2)) * dir
        );
      }
      case "dueDate":
        return (
          (new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime()) * dir
        );
      default:
        return 0;
    }
  });

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDirection("asc");
    }
  }

  const maturityValue = (level: NIS2Article["maturityLevel"]): number => {
    const map: Record<string, number> = {
      initial: 1,
      developing: 2,
      defined: 3,
      managed: 4,
      optimized: 5,
    };
    return map[level] ?? 1;
  };

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <ShieldCheck className="h-7 w-7 text-accent" />
          <h1 className="text-2xl font-bold text-white">
            NIS2 Compliance
          </h1>
        </div>
        <p className="text-sm text-gray-400">
          Directive (EU) 2022/2555 - Article 21 cybersecurity risk-management
          measures
        </p>
      </div>

      {/* Overall Score */}
      <div className="mb-8 card">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Overall Compliance Score
            </h2>
            <p className="text-sm text-gray-400">
              Across all 10 Article 21(2) measures
            </p>
          </div>
          <span
            className={`text-4xl font-bold ${getScoreColor(data.overallScore)}`}
          >
            {data.overallScore}%
          </span>
        </div>
        <div className="mt-4 h-3 w-full overflow-hidden rounded-full bg-gray-700/50">
          <div
            className={`h-full rounded-full ${getScoreBarColor(data.overallScore)} transition-all duration-700`}
            style={{ width: `${data.overallScore}%` }}
          />
        </div>
      </div>

      {/* Per-Article Scores */}
      <div className="mb-8">
        <h2 className="mb-4 text-lg font-semibold text-white">
          Per-Article Assessment
        </h2>
        <div className="space-y-3">
          {data.articles.map((article) => {
            const percentage = Math.round(
              (article.score / article.maxScore) * 100
            );
            const isExpanded = expandedArticle === article.id;
            const matLevel = maturityValue(article.maturityLevel);

            return (
              <div
                key={article.id}
                className="card overflow-hidden transition-all duration-200"
              >
                <button
                  className="flex w-full items-center gap-4 text-left"
                  onClick={() =>
                    setExpandedArticle(isExpanded ? null : article.id)
                  }
                >
                  {isExpanded ? (
                    <ChevronDown className="h-4 w-4 text-gray-500 flex-shrink-0" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-gray-500 flex-shrink-0" />
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono text-accent">
                        {article.id}
                      </span>
                      <span className="text-sm font-medium text-white truncate">
                        {article.name}
                      </span>
                    </div>
                    <p className="text-xs text-gray-500 truncate">
                      {article.description}
                    </p>
                  </div>
                  <div className="flex items-center gap-4 flex-shrink-0">
                    {/* Maturity Level Indicator */}
                    <div className="flex gap-1">
                      {maturityLevels.map((ml) => (
                        <div
                          key={ml.key}
                          className={`h-3 w-6 rounded-sm ${
                            ml.value <= matLevel
                              ? ml.color
                              : "bg-gray-700/50"
                          }`}
                          title={ml.label}
                        />
                      ))}
                    </div>
                    <span
                      className={`text-lg font-bold ${getScoreColor(percentage)} w-14 text-right`}
                    >
                      {percentage}%
                    </span>
                  </div>
                </button>

                {isExpanded && (
                  <div className="mt-4 border-t border-gray-700/30 pt-4">
                    {/* Score Bar */}
                    <div className="mb-4">
                      <div className="h-2 w-full overflow-hidden rounded-full bg-gray-700/50">
                        <div
                          className={`h-full rounded-full ${getScoreBarColor(percentage)} transition-all duration-500`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>

                    {/* Maturity Level Detail */}
                    <div className="mb-4 flex items-center gap-2">
                      <span className="text-xs text-gray-500">
                        Maturity Level:
                      </span>
                      <span className="text-sm font-medium text-gray-200 capitalize">
                        {article.maturityLevel}
                      </span>
                      <span className="text-xs text-gray-500">
                        ({matLevel}/5)
                      </span>
                    </div>

                    {/* Gaps */}
                    {article.gaps.length > 0 && (
                      <div>
                        <h4 className="mb-2 text-sm font-medium text-gray-300">
                          Identified Gaps ({article.gaps.length})
                        </h4>
                        <div className="space-y-2">
                          {article.gaps.map((gap) => {
                            const StatusIcon =
                              statusIcon[gap.status] ?? AlertCircle;

                            return (
                              <div
                                key={gap.id}
                                className="rounded-lg bg-primary/50 p-3"
                              >
                                <div className="flex items-start justify-between gap-4">
                                  <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                      <span
                                        className={
                                          priorityBadge[gap.priority] ??
                                          "badge-low"
                                        }
                                      >
                                        {gap.priority}
                                      </span>
                                      <StatusIcon className="h-3.5 w-3.5 text-gray-400" />
                                      <span className="text-xs capitalize text-gray-400">
                                        {gap.status.replace("_", " ")}
                                      </span>
                                    </div>
                                    <p className="text-sm text-gray-300">
                                      {gap.description}
                                    </p>
                                    <p className="mt-1 text-xs text-gray-500">
                                      Remediation: {gap.remediation}
                                    </p>
                                  </div>
                                  <span className="text-xs text-gray-500 whitespace-nowrap">
                                    Due:{" "}
                                    {new Date(gap.dueDate).toLocaleDateString(
                                      "en-US",
                                      {
                                        month: "short",
                                        day: "numeric",
                                        year: "numeric",
                                      }
                                    )}
                                  </span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Gap Analysis Table */}
      <div className="mb-8 card">
        <h2 className="mb-4 text-lg font-semibold text-white">
          Gap Analysis & Action Plan
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-gray-700/50">
                <th className="pb-3 pr-4 text-xs font-medium uppercase tracking-wider text-gray-500">
                  ID
                </th>
                <th className="pb-3 pr-4 text-xs font-medium uppercase tracking-wider text-gray-500">
                  Article
                </th>
                <th
                  className="pb-3 pr-4 text-xs font-medium uppercase tracking-wider text-gray-500 cursor-pointer hover:text-gray-300 transition-colors"
                  onClick={() => toggleSort("priority")}
                >
                  <div className="flex items-center gap-1">
                    Priority
                    <ArrowUpDown className="h-3 w-3" />
                  </div>
                </th>
                <th className="pb-3 pr-4 text-xs font-medium uppercase tracking-wider text-gray-500">
                  Description
                </th>
                <th
                  className="pb-3 pr-4 text-xs font-medium uppercase tracking-wider text-gray-500 cursor-pointer hover:text-gray-300 transition-colors"
                  onClick={() => toggleSort("status")}
                >
                  <div className="flex items-center gap-1">
                    Status
                    <ArrowUpDown className="h-3 w-3" />
                  </div>
                </th>
                <th
                  className="pb-3 text-xs font-medium uppercase tracking-wider text-gray-500 cursor-pointer hover:text-gray-300 transition-colors"
                  onClick={() => toggleSort("dueDate")}
                >
                  <div className="flex items-center gap-1">
                    Due Date
                    <ArrowUpDown className="h-3 w-3" />
                  </div>
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedGaps.map((gap) => {
                const StatusIcon = statusIcon[gap.status] ?? AlertCircle;

                return (
                  <tr key={gap.id} className="table-row">
                    <td className="py-3 pr-4 font-mono text-xs text-gray-500">
                      {gap.id}
                    </td>
                    <td className="py-3 pr-4 text-xs text-gray-400 max-w-[120px] truncate">
                      {gap.articleName}
                    </td>
                    <td className="py-3 pr-4">
                      <span
                        className={
                          priorityBadge[gap.priority] ?? "badge-low"
                        }
                      >
                        {gap.priority}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-sm text-gray-300 max-w-xs truncate">
                      {gap.description}
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-1.5">
                        <StatusIcon className="h-3.5 w-3.5 text-gray-400" />
                        <span className="text-xs capitalize text-gray-400">
                          {gap.status.replace("_", " ")}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 text-xs text-gray-400">
                      {new Date(gap.dueDate).toLocaleDateString("en-US", {
                        month: "short",
                        day: "numeric",
                      })}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
