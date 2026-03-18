"use client";

import React, { useEffect, useState } from "react";
import {
  AlertTriangle,
  ShieldAlert,
  Bell,
  Cloud,
  Activity,
  ArrowUpRight,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  Area,
  AreaChart,
} from "recharts";
import SecurityScore from "@/components/SecurityScore";
import StatCard from "@/components/StatCard";
import NIS2Radar from "@/components/NIS2Radar";
import AlertsTable from "@/components/AlertsTable";
import {
  fetchSecurityScore,
  fetchFindings,
  fetchNIS2Compliance,
  fetchAlerts,
  fetchCloudPosture,
} from "@/lib/api";
import type {
  SecurityScore as SecurityScoreType,
  FindingsSummary,
  NIS2Compliance,
  AlertsResponse,
  CloudPosture,
} from "@/lib/types";

export default function DashboardPage() {
  const [scoreData, setScoreData] = useState<SecurityScoreType | null>(null);
  const [findings, setFindings] = useState<FindingsSummary | null>(null);
  const [nis2, setNis2] = useState<NIS2Compliance | null>(null);
  const [alerts, setAlerts] = useState<AlertsResponse | null>(null);
  const [cloudPosture, setCloudPosture] = useState<CloudPosture | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [scoreRes, findingsRes, nis2Res, alertsRes, cloudRes] =
          await Promise.all([
            fetchSecurityScore(),
            fetchFindings(),
            fetchNIS2Compliance(),
            fetchAlerts({ pageSize: 10 }),
            fetchCloudPosture(),
          ]);
        setScoreData(scoreRes);
        setFindings(findingsRes);
        setNis2(nis2Res);
        setAlerts(alertsRes);
        setCloudPosture(cloudRes);
      } catch (err) {
        console.error("Failed to load dashboard data:", err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="flex h-[80vh] items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-gray-700 border-t-accent" />
          <p className="text-sm text-gray-400">Loading security posture...</p>
        </div>
      </div>
    );
  }

  const severityChartData = findings
    ? [
        { name: "Critical", count: findings.critical, fill: "#ef4444" },
        { name: "High", count: findings.high, fill: "#f97316" },
        { name: "Medium", count: findings.medium, fill: "#eab308" },
        { name: "Low", count: findings.low, fill: "#3b82f6" },
        { name: "Info", count: findings.info, fill: "#6b7280" },
      ]
    : [];

  return (
    <div>
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Security Posture Dashboard
          </h1>
          <p className="mt-1 text-sm text-gray-400">
            Real-time overview of your organization&apos;s security posture
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 rounded-lg bg-green-500/10 px-3 py-1.5">
            <div className="h-2 w-2 animate-pulse rounded-full bg-green-500" />
            <span className="text-xs font-medium text-green-400">
              Systems Operational
            </span>
          </div>
          <span className="text-xs text-gray-500">
            Last updated: {new Date().toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* Top Section: Security Score + Stats */}
      <div className="mb-8 grid grid-cols-12 gap-6">
        {/* Security Score */}
        <div className="col-span-4 card flex flex-col items-center justify-center">
          {scoreData && (
            <>
              <SecurityScore score={scoreData.score} />
              <div className="mt-4 flex items-center gap-2">
                <ArrowUpRight className="h-4 w-4 text-green-400" />
                <span className="text-sm font-medium text-green-400">
                  +{scoreData.trendValue}%
                </span>
                <span className="text-xs text-gray-500">vs last week</span>
              </div>
              {/* Score Breakdown */}
              <div className="mt-6 w-full space-y-2">
                {Object.entries(scoreData.breakdown).map(([key, value]) => (
                  <div key={key} className="flex items-center gap-3">
                    <span className="w-28 text-xs text-gray-400 capitalize">
                      {key.replace(/([A-Z])/g, " $1").trim()}
                    </span>
                    <div className="flex-1 h-1.5 rounded-full bg-gray-700/50 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          value >= 70
                            ? "bg-green-500"
                            : value >= 40
                              ? "bg-yellow-500"
                              : "bg-red-500"
                        }`}
                        style={{ width: `${value}%` }}
                      />
                    </div>
                    <span className="w-8 text-right text-xs font-medium text-gray-300">
                      {value}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Stat Cards */}
        <div className="col-span-8 grid grid-cols-2 gap-4">
          <StatCard
            title="Critical Findings"
            value={findings?.critical ?? 0}
            icon={AlertTriangle}
            trend="down"
            trendValue="-2"
            trendLabel="vs last week"
            variant="critical"
          />
          <StatCard
            title="High Findings"
            value={findings?.high ?? 0}
            icon={ShieldAlert}
            trend="down"
            trendValue="-5"
            trendLabel="vs last week"
            variant="warning"
          />
          <StatCard
            title="Alerts Today"
            value={alerts?.total ?? 0}
            icon={Bell}
            trend="up"
            trendValue="+3"
            trendLabel="vs yesterday"
            variant="default"
          />
          <StatCard
            title="Cloud Score"
            value={`${cloudPosture?.score ?? 0}%`}
            icon={Cloud}
            trend="up"
            trendValue={`+${cloudPosture?.trendValue ?? 0}%`}
            trendLabel="vs last scan"
            variant="success"
          />
        </div>
      </div>

      {/* Charts Row */}
      <div className="mb-8 grid grid-cols-2 gap-6">
        {/* Findings by Severity */}
        <div className="card">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">
              Findings by Severity
            </h3>
            <Activity className="h-5 w-5 text-gray-500" />
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityChartData} barCategoryGap="20%">
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#16213e",
                    border: "1px solid rgba(107,114,128,0.3)",
                    borderRadius: "8px",
                    color: "#e5e7eb",
                  }}
                />
                <Bar
                  dataKey="count"
                  radius={[4, 4, 0, 0]}
                  fill="#e94560"
                  name="Count"
                >
                  {severityChartData.map((entry, index) => (
                    <rect key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Cloud Posture Trend */}
        <div className="card">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">
              Cloud Posture Trend
            </h3>
            <Cloud className="h-5 w-5 text-gray-500" />
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={cloudPosture?.history ?? []}>
                <defs>
                  <linearGradient
                    id="cloudScoreGradient"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop offset="5%" stopColor="#e94560" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#e94560" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(val: string) =>
                    new Date(val).toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                    })
                  }
                />
                <YAxis
                  domain={[60, 100]}
                  tick={{ fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#16213e",
                    border: "1px solid rgba(107,114,128,0.3)",
                    borderRadius: "8px",
                    color: "#e5e7eb",
                  }}
                  labelFormatter={(val: string) =>
                    new Date(val).toLocaleDateString("en-US", {
                      month: "long",
                      day: "numeric",
                      year: "numeric",
                    })
                  }
                />
                <Area
                  type="monotone"
                  dataKey="score"
                  stroke="#e94560"
                  strokeWidth={2}
                  fill="url(#cloudScoreGradient)"
                  name="Score"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* NIS2 + Alerts Row */}
      <div className="grid grid-cols-2 gap-6">
        {/* NIS2 Compliance */}
        {nis2 && (
          <NIS2Radar
            articles={nis2.articles}
            overallScore={nis2.overallScore}
          />
        )}

        {/* Recent Alerts */}
        <div className="card">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">
              Recent Alerts
            </h3>
            <a
              href="/alerts"
              className="text-xs font-medium text-accent hover:text-accent/80 transition-colors"
            >
              View all
            </a>
          </div>
          {alerts && (
            <AlertsTable
              alerts={alerts.alerts}
              total={alerts.total}
              page={alerts.page}
              pageSize={alerts.pageSize}
              compact
            />
          )}
        </div>
      </div>
    </div>
  );
}
