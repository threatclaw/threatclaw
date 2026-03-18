"use client";

import React from "react";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ElementType;
  trend?: "up" | "down" | "stable";
  trendValue?: string;
  trendLabel?: string;
  variant?: "default" | "critical" | "warning" | "success";
}

const variantStyles = {
  default: {
    iconBg: "bg-success/30",
    iconColor: "text-blue-400",
  },
  critical: {
    iconBg: "bg-red-500/20",
    iconColor: "text-red-400",
  },
  warning: {
    iconBg: "bg-yellow-500/20",
    iconColor: "text-yellow-400",
  },
  success: {
    iconBg: "bg-green-500/20",
    iconColor: "text-green-400",
  },
};

export default function StatCard({
  title,
  value,
  icon: Icon,
  trend,
  trendValue,
  trendLabel,
  variant = "default",
}: StatCardProps) {
  const styles = variantStyles[variant];

  const trendConfig = {
    up: { icon: TrendingUp, color: "text-green-400", bg: "bg-green-500/10" },
    down: { icon: TrendingDown, color: "text-red-400", bg: "bg-red-500/10" },
    stable: { icon: Minus, color: "text-gray-400", bg: "bg-gray-500/10" },
  };

  return (
    <div className="card-hover">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-400">{title}</p>
          <p className="mt-2 text-3xl font-bold text-white">{value}</p>
        </div>
        <div className={`rounded-lg p-2.5 ${styles.iconBg}`}>
          <Icon className={`h-5 w-5 ${styles.iconColor}`} />
        </div>
      </div>
      {trend && trendValue && (
        <div className="mt-4 flex items-center gap-2">
          <div
            className={`flex items-center gap-1 rounded-full px-2 py-0.5 ${trendConfig[trend].bg}`}
          >
            {React.createElement(trendConfig[trend].icon, {
              className: `h-3 w-3 ${trendConfig[trend].color}`,
            })}
            <span className={`text-xs font-medium ${trendConfig[trend].color}`}>
              {trendValue}
            </span>
          </div>
          {trendLabel && (
            <span className="text-xs text-gray-500">{trendLabel}</span>
          )}
        </div>
      )}
    </div>
  );
}
