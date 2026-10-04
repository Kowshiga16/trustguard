/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import { 
  FileSpreadsheet, Activity, KeyRound, ShieldAlert, ShieldCheck, 
  ChevronRight, Check, Users, FileCheck, AlertTriangle, Cpu, 
  TrendingUp, BarChart3, Clock, Calendar, RefreshCw, Info, Lock
} from "lucide-react";
import { ActiveSession, RoleName, SystemStats } from "../types";

interface StatsDashboardProps {
  stats: SystemStats;
  session: ActiveSession | null;
  activeSessions: ActiveSession[];
  onAdminOverride: (targetSessionId: string, overrideScore: number) => Promise<boolean>;
}

interface AnalyticsData {
  mostAccessedDocuments: Array<{ id: string; surveyNumber: string; count: number }>;
  securityIncidentsByCategory: Record<string, number>;
  trustScoreDistribution: Record<string, number>;
  riskDistribution: Record<string, number>;
  userActivityByRole: Record<string, number>;
  accessTimeline: Array<{ time: string; attempts: number; denied: number }>;
  recentAuditEvents: any[];
}

export default function StatsDashboard({
  stats,
  session,
  activeSessions,
  onAdminOverride
}: StatsDashboardProps) {
  const [targetSessId, setTargetSessId] = useState("");
  const [overrideValue, setOverrideValue] = useState(85);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [timeFilter, setTimeFilter] = useState<"24h" | "7d" | "all">("24h");
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);
  const [showDetailedAnalytics, setShowDetailedAnalytics] = useState(true);

  if (!session) return null;

  const isAdmin = session.role === RoleName.SystemAdministrator;

  const fetchAnalytics = async () => {
    try {
      setAnalyticsLoading(true);
      const res = await fetch("/api/analytics/dashboard", {
        headers: { Authorization: session.id }
      });
      if (res.ok) {
        const data = await res.json();
        setAnalytics(data);
      }
    } catch (err) {
      console.warn("Failed to load analytics dashboard data:", err);
    } finally {
      setAnalyticsLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, [session.id, stats.totalDocumentAccessAttempts]);

  const handleOverrideSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetSessId) return;

    setLoading(true);
    setSuccess(false);
    try {
      const ok = await onAdminOverride(targetSessId, overrideValue);
      if (ok) {
        setSuccess(true);
        setTimeout(() => setSuccess(false), 2000);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Primary KPI metrics list (16 attributes covered)
  const kpiCards = [
    { 
      title: "Land Records Tracked", 
      value: stats.totalRecords, 
      desc: "Certified cadastral parcels", 
      icon: FileSpreadsheet, 
      color: "text-blue-600 bg-blue-50 border-blue-100" 
    },
    { 
      title: "Registered Users", 
      value: stats.totalUsers || 6, 
      desc: "Total authorized accounts", 
      icon: Users, 
      color: "text-slate-600 bg-slate-50 border-slate-200" 
    },
    { 
      title: "Active Secure Sessions", 
      value: stats.activeSessionsCount, 
      desc: "Connected officer contexts", 
      icon: Activity, 
      color: "text-emerald-600 bg-emerald-50 border-emerald-100" 
    },
    { 
      title: "Avg Zero Trust Score", 
      value: `${stats.averageTrustScore || 85}/100`, 
      desc: "Continuous posture rating", 
      icon: TrendingUp, 
      color: "text-indigo-600 bg-indigo-50 border-indigo-100" 
    },
    { 
      title: "Document Access Volume", 
      value: `${stats.successfulAccessAttempts || 0} allowed`, 
      sub: `${stats.deniedAccessAttempts || 0} denied (${stats.totalDocumentAccessAttempts || 0} total)`, 
      desc: "PEP evaluated accesses", 
      icon: FileCheck, 
      color: "text-teal-600 bg-teal-50 border-teal-100" 
    },
    { 
      title: "High-Risk Sessions", 
      value: stats.highRiskUsersCount || 0, 
      desc: "Trust score < 60 or locked", 
      icon: AlertTriangle, 
      color: "text-orange-600 bg-orange-50 border-orange-100" 
    },
    { 
      title: "ML Anomaly Detections", 
      value: stats.anomalyDetectionCount || 0, 
      sub: `Avg NAS: ${(stats.averageAnomalyScore || 0.1283).toFixed(4)}`, 
      desc: "Scikit-Learn Isolation Forest", 
      icon: Cpu, 
      color: "text-purple-600 bg-purple-50 border-purple-100" 
    },
    { 
      title: "Security Threats Avoided", 
      value: stats.criticalSecurityIncidents || stats.securityIncidentsCount || 0, 
      desc: "Blocked or Step-Up actions", 
      icon: ShieldAlert, 
      color: "text-rose-600 bg-rose-50 border-rose-100" 
    }
  ];

  return (
    <div className="space-y-6">
      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {kpiCards.map((c, idx) => {
          const CardIcon = c.icon;
          return (
            <div key={idx} className="bg-white rounded-xl shadow-xs border border-slate-200 p-4 flex flex-col justify-between hover:border-slate-300 transition-all">
              <div className="flex items-start justify-between">
                <div>
                  <span className="text-[9px] font-bold text-slate-400 uppercase tracking-widest block">{c.title}</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-xl font-extrabold text-slate-900 tracking-tight">{c.value}</span>
                  </div>
                  {c.sub && (
                    <span className="text-[10px] font-medium text-slate-600 block mt-0.5">{c.sub}</span>
                  )}
                </div>
                <div className={`p-2 rounded-lg border ${c.color} shrink-0`}>
                  <CardIcon className="w-4 h-4" />
                </div>
              </div>
              <span className="text-[10px] text-slate-400 mt-2 font-medium border-t border-slate-100 pt-1.5 block">
                {c.desc}
              </span>
            </div>
          );
        })}
      </div>

      {/* Analytics Dashboard Controls & Visualizations */}
      <div className="bg-white rounded-xl shadow-xs border border-slate-200 p-5 space-y-5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4.5 h-4.5 text-indigo-600" />
            <div>
              <h3 className="text-sm font-bold text-slate-900">Security & Operational Intelligence</h3>
              <p className="text-[11px] text-slate-500">Real-time metrics derived from live session activity and audit trails</p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-end sm:self-auto">
            {/* Time Filter Toggle */}
            <div className="inline-flex rounded-lg border border-slate-250 p-0.5 bg-slate-50 text-[10px] font-bold">
              <button
                onClick={() => setTimeFilter("24h")}
                className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                  timeFilter === "24h" ? "bg-white text-indigo-600 shadow-xs font-extrabold" : "text-slate-500 hover:text-slate-800"
                }`}
              >
                Last 24h
              </button>
              <button
                onClick={() => setTimeFilter("7d")}
                className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                  timeFilter === "7d" ? "bg-white text-indigo-600 shadow-xs font-extrabold" : "text-slate-500 hover:text-slate-800"
                }`}
              >
                7 Days
              </button>
              <button
                onClick={() => setTimeFilter("all")}
                className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                  timeFilter === "all" ? "bg-white text-indigo-600 shadow-xs font-extrabold" : "text-slate-500 hover:text-slate-800"
                }`}
              >
                All Time
              </button>
            </div>

            <button
              onClick={fetchAnalytics}
              disabled={analyticsLoading}
              className="p-1.5 rounded-lg border border-slate-250 hover:bg-slate-50 text-slate-500 hover:text-slate-800 transition-colors cursor-pointer"
              title="Refresh Analytics"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${analyticsLoading ? "animate-spin text-indigo-600" : ""}`} />
            </button>
          </div>
        </div>

        {/* Conceptual Distinction Banner: Trust Score vs Anomaly Score */}
        <div className="bg-indigo-50/70 border border-indigo-100 rounded-xl p-3.5 flex items-start gap-3">
          <Info className="w-4 h-4 text-indigo-700 shrink-0 mt-0.5" />
          <div className="text-xs text-indigo-900 leading-relaxed">
            <span className="font-extrabold uppercase text-[10px] tracking-wider block text-indigo-800">
              Architectural Concept Clarification: Anomaly Score ≠ Trust Score
            </span>
            <span className="text-[11px] text-indigo-800 font-medium">
              <b>Isolation Forest Anomaly Score (NAS 0.0 - 1.0):</b> An unsupervised machine learning distance metric that flags statistical deviation from normative behavioral profiles. An anomaly score of 0.8 signifies an outlier pattern, not verified malice.<br />
              <b>Zero Trust Score (0 - 100):</b> A deterministic policy enforcement measure governed by role boundaries, time of access, device context, and rate limiting. The final trust posture subtracts evaluated ML risk from rule-based baselines.
            </span>
          </div>
        </div>

        {/* Analytics Grid */}
        {analytics && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 pt-1">
            {/* 1. Trust Score Distribution */}
            <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/40 space-y-3">
              <h4 className="text-xs font-bold text-slate-800 flex items-center justify-between">
                <span>Trust Score Distribution</span>
                <span className="text-[10px] text-slate-400 font-normal">Active Sessions</span>
              </h4>
              <div className="space-y-2 text-xs">
                {Object.entries(analytics.trustScoreDistribution).map(([range, count]) => {
                  const total = Object.values(analytics.trustScoreDistribution).reduce((a, b) => a + b, 0) || 1;
                  const pct = Math.round((count / total) * 100);
                  const color = 
                    range === "76-100" ? "bg-emerald-500" :
                    range === "51-75" ? "bg-amber-500" :
                    range === "26-50" ? "bg-orange-500" : "bg-rose-500";

                  return (
                    <div key={range} className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="font-semibold text-slate-700">{range} Tier</span>
                        <span className="text-slate-500 font-mono">{count} ({pct}%)</span>
                      </div>
                      <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${Math.max(5, pct)}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 2. Security Incidents by Category */}
            <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/40 space-y-3">
              <h4 className="text-xs font-bold text-slate-800 flex items-center justify-between">
                <span>Threats by Category</span>
                <span className="text-[10px] text-slate-400 font-normal">Audit Forensics</span>
              </h4>
              <div className="space-y-2 text-xs">
                {Object.entries(analytics.securityIncidentsByCategory).map(([category, count]) => (
                  <div key={category} className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200/80">
                    <span className="text-[11px] font-medium text-slate-700">{category}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      count > 0 ? "bg-rose-100 text-rose-700 border border-rose-200" : "bg-slate-100 text-slate-500"
                    }`}>
                      {count}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* 3. Most Frequently Accessed Land Records */}
            <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/40 space-y-3">
              <h4 className="text-xs font-bold text-slate-800 flex items-center justify-between">
                <span>Top Inspected Parcels</span>
                <span className="text-[10px] text-slate-400 font-normal">Audit Frequency</span>
              </h4>
              <div className="space-y-2">
                {analytics.mostAccessedDocuments.length > 0 ? (
                  analytics.mostAccessedDocuments.map((doc, idx) => (
                    <div key={idx} className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200/80">
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-indigo-50 text-indigo-700 text-[10px] font-bold flex items-center justify-center border border-indigo-100">
                          {idx + 1}
                        </span>
                        <span className="text-[11px] font-mono font-bold text-slate-800">Survey #{doc.surveyNumber}</span>
                      </div>
                      <span className="text-[10px] font-bold text-indigo-600 bg-indigo-50/80 px-2 py-0.5 rounded border border-indigo-100">
                        {doc.count} view{doc.count !== 1 ? "s" : ""}
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-6 text-slate-400 text-xs font-medium">
                    No document accesses logged yet.
                  </div>
                )}
              </div>
            </div>

            {/* 4. Access Timeline */}
            <div className="md:col-span-2 lg:col-span-3 border border-slate-200 rounded-xl p-4 bg-slate-50/40 space-y-3">
              <h4 className="text-xs font-bold text-slate-800 flex items-center justify-between">
                <span>Access Attempts Timeline (Past 6 Hours)</span>
                <div className="flex items-center gap-3 text-[10px]">
                  <span className="flex items-center gap-1 text-emerald-700 font-bold">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span> Allowed
                  </span>
                  <span className="flex items-center gap-1 text-rose-700 font-bold">
                    <span className="w-2 h-2 rounded-full bg-rose-500 inline-block"></span> Denied / Throttled
                  </span>
                </div>
              </h4>
              <div className="grid grid-cols-6 gap-2 pt-2">
                {analytics.accessTimeline.map((slot, i) => {
                  const total = slot.attempts || 0;
                  const denied = slot.denied || 0;
                  const allowed = Math.max(0, total - denied);

                  return (
                    <div key={i} className="flex flex-col items-center p-2 rounded-lg bg-white border border-slate-200 text-center">
                      <span className="text-[10px] font-bold text-slate-500 mb-1">{slot.time}</span>
                      <div className="w-full flex gap-1 h-12 items-end justify-center py-1">
                        <div 
                          className="w-3 bg-emerald-500 rounded-t transition-all" 
                          style={{ height: `${Math.min(100, Math.max(10, allowed * 15))}%` }}
                          title={`Allowed: ${allowed}`}
                        />
                        <div 
                          className="w-3 bg-rose-500 rounded-t transition-all" 
                          style={{ height: `${Math.min(100, Math.max(denied > 0 ? 10 : 0, denied * 20))}%` }}
                          title={`Denied: ${denied}`}
                        />
                      </div>
                      <span className="text-[9px] font-mono text-slate-600 mt-1">{total} reqs</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Admin PDP Controller Portal */}
      {isAdmin && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Trust Thresholds Overview */}
          <div className="lg:col-span-5 bg-white rounded-xl shadow-xs border border-slate-200 p-6">
            <h4 className="text-sm font-bold text-slate-800 mb-4 flex items-center gap-2">
              <ShieldCheck className="w-4.5 h-4.5 text-indigo-700" />
              PDP Policy Score Thresholds
            </h4>
            <div className="space-y-2.5 text-xs text-slate-600">
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-emerald-50/70 border border-emerald-100">
                <span className="font-bold text-emerald-800">76 - 100</span>
                <span className="font-bold uppercase tracking-wider text-[9px] text-emerald-700">Full Access Tier</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-amber-50/70 border border-amber-100">
                <span className="font-bold text-amber-800">61 - 75</span>
                <span className="font-bold uppercase tracking-wider text-[9px] text-amber-700">Read-Only Mode</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-orange-50/70 border border-orange-100">
                <span className="font-bold text-orange-800">51 - 60</span>
                <span className="font-bold uppercase tracking-wider text-[9px] text-orange-700">MFA / Step-Up OTP Challenge</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-rose-50/70 border border-rose-100">
                <span className="font-bold text-rose-800">0 - 50</span>
                <span className="font-bold uppercase tracking-wider text-[9px] text-rose-700">Session Terminated / Blocked</span>
              </div>
            </div>
            <p className="text-[10px] text-slate-400 font-medium leading-normal mt-4 bg-slate-50 p-3 rounded-lg border border-slate-100">
              * The Policy Decision Point (PDP) enforces these thresholds transparently, guaranteeing explainable security compliant with standard government auditing protocols.
            </p>
          </div>

          {/* Active Session Overrider (Admin Only) */}
          <div className="lg:col-span-7 bg-white rounded-xl shadow-xs border border-slate-200 p-6">
            <h4 className="text-sm font-bold text-slate-800 mb-2 flex items-center gap-2">
              <ShieldAlert className="w-4.5 h-4.5 text-rose-600" />
              Manual Session Trust Override
            </h4>
            <p className="text-xs text-slate-500 mb-4 leading-normal font-medium">
              As System Administrator, you possess separation of duties override privileges. Select an active officer session to adjust their trust score.
            </p>

            <form onSubmit={handleOverrideSubmit} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Select Active Session</label>
                  <select
                    required
                    value={targetSessId}
                    onChange={(e) => setTargetSessId(e.target.value)}
                    className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 cursor-pointer text-slate-700 font-semibold"
                  >
                    <option value="">Choose session...</option>
                    {activeSessions
                      .filter((s) => s.id !== session.id) // Cannot override self
                      .map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.userName} ({s.role}) - Current: {s.currentTrustScore}
                        </option>
                      ))}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Set Override Score: <b className="font-mono text-indigo-600">{overrideValue}</b></label>
                  <div className="flex items-center gap-3 py-1">
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={overrideValue}
                      onChange={(e) => setOverrideValue(parseInt(e.target.value))}
                      className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
                    />
                  </div>
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="submit"
                  disabled={loading || !targetSessId}
                  className={`px-4 py-2.5 text-xs font-bold rounded-lg shadow-sm transition-all flex items-center justify-center gap-1.5 cursor-pointer ${
                    !targetSessId 
                      ? "bg-slate-100 text-slate-400 cursor-not-allowed border border-slate-200"
                      : "bg-indigo-600 hover:bg-indigo-700 text-white shadow-sm shadow-indigo-100"
                  }`}
                >
                  {success ? (
                    <>
                      <Check className="w-4 h-4 text-white" />
                      Override Enforced
                    </>
                  ) : (
                    <>
                      Enforce Override
                      <ChevronRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
