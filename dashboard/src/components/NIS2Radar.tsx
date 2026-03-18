"use client";

import React from "react";
import type { NIS2Article } from "@/lib/types";

interface NIS2RadarProps {
  articles: NIS2Article[];
  overallScore: number;
}

function getScoreColor(score: number): string {
  if (score >= 80) return "bg-green-500";
  if (score >= 60) return "bg-yellow-500";
  if (score >= 40) return "bg-orange-500";
  return "bg-red-500";
}

function getScoreTextColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

function getMaturityBadge(level: NIS2Article["maturityLevel"]): {
  label: string;
  color: string;
} {
  const map: Record<string, { label: string; color: string }> = {
    initial: { label: "Initial", color: "bg-red-500/20 text-red-400" },
    developing: {
      label: "Developing",
      color: "bg-orange-500/20 text-orange-400",
    },
    defined: { label: "Defined", color: "bg-yellow-500/20 text-yellow-400" },
    managed: { label: "Managed", color: "bg-blue-500/20 text-blue-400" },
    optimized: {
      label: "Optimized",
      color: "bg-green-500/20 text-green-400",
    },
  };
  return map[level] ?? map.initial;
}

export default function NIS2Radar({ articles, overallScore }: NIS2RadarProps) {
  return (
    <div className="card">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white">
            NIS2 Compliance
          </h3>
          <p className="text-sm text-gray-400">Article 21 - Security measures</p>
        </div>
        <div className="text-right">
          <span
            className={`text-3xl font-bold ${getScoreTextColor(overallScore)}`}
          >
            {overallScore}%
          </span>
          <p className="text-xs text-gray-500">Overall Score</p>
        </div>
      </div>
      <div className="space-y-4">
        {articles.map((article) => {
          const percentage = Math.round(
            (article.score / article.maxScore) * 100
          );
          const maturity = getMaturityBadge(article.maturityLevel);

          return (
            <div key={article.id} className="group">
              <div className="mb-1.5 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-gray-500">
                    {article.id.replace("art21_2", "").toUpperCase()}
                  </span>
                  <span className="text-sm text-gray-300 group-hover:text-white transition-colors truncate max-w-[200px]">
                    {article.name}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${maturity.color}`}
                  >
                    {maturity.label}
                  </span>
                  <span
                    className={`text-sm font-semibold ${getScoreTextColor(percentage)}`}
                  >
                    {percentage}%
                  </span>
                </div>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-gray-700/50">
                <div
                  className={`h-full rounded-full ${getScoreColor(percentage)} transition-all duration-500`}
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
