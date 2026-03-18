"use client";

import React from "react";

interface SecurityScoreProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  label?: string;
}

function getScoreColor(score: number): string {
  if (score < 40) return "#ef4444"; // red
  if (score < 70) return "#e8a838"; // orange/warning
  return "#22c55e"; // green
}

function getScoreGradientId(score: number): string {
  if (score < 40) return "score-gradient-red";
  if (score < 70) return "score-gradient-orange";
  return "score-gradient-green";
}

export default function SecurityScore({
  score,
  size = 200,
  strokeWidth = 12,
  label = "Security Score",
}: SecurityScoreProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (score / 100) * circumference;
  const center = size / 2;
  const color = getScoreColor(score);

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          className="-rotate-90 transform"
        >
          <defs>
            <linearGradient
              id="score-gradient-red"
              x1="0%"
              y1="0%"
              x2="100%"
              y2="0%"
            >
              <stop offset="0%" stopColor="#ef4444" />
              <stop offset="100%" stopColor="#f87171" />
            </linearGradient>
            <linearGradient
              id="score-gradient-orange"
              x1="0%"
              y1="0%"
              x2="100%"
              y2="0%"
            >
              <stop offset="0%" stopColor="#e8a838" />
              <stop offset="100%" stopColor="#fbbf24" />
            </linearGradient>
            <linearGradient
              id="score-gradient-green"
              x1="0%"
              y1="0%"
              x2="100%"
              y2="0%"
            >
              <stop offset="0%" stopColor="#22c55e" />
              <stop offset="100%" stopColor="#4ade80" />
            </linearGradient>
          </defs>
          {/* Background circle */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="#374151"
            strokeWidth={strokeWidth}
            strokeOpacity={0.3}
          />
          {/* Score arc */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={`url(#${getScoreGradientId(score)})`}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-5xl font-bold"
            style={{ color }}
          >
            {score}
          </span>
          <span className="text-sm text-gray-400">/ 100</span>
        </div>
      </div>
      <span className="text-sm font-medium text-gray-400">{label}</span>
    </div>
  );
}
