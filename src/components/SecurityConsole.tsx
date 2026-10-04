/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { ShieldCheck, ShieldAlert, FileText, Search, RefreshCw, Terminal, Eye, Lock, Mail, AlertTriangle } from "lucide-react";
import { TrustLog, AuditLog } from "../types";

interface SecurityConsoleProps {
  trustLogs: TrustLog[];
  auditLogs: AuditLog[];
  onRefresh: () => void;
}

export default function SecurityConsole({
  trustLogs,
  auditLogs,
  onRefresh
}: SecurityConsoleProps) {
  const [auditSearch, setAuditSearch] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("all");

  const filteredAudits = auditLogs.filter((al) => {
    const matchesSearch = 
      al.userName.toLowerCase().includes(auditSearch.toLowerCase()) ||
      al.role.toLowerCase().includes(auditSearch.toLowerCase()) ||
      al.actionPerformed.toLowerCase().includes(auditSearch.toLowerCase()) ||
      al.resourceAccessed.toLowerCase().includes(auditSearch.toLowerCase());

    const matchesFilter = decisionFilter === "all" || al.decision === decisionFilter;
    return matchesSearch && matchesFilter;
  });

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-full">
      {/* PDP Trust Score Log Column */}
      <div className="lg:col-span-5 bg-slate-900 text-slate-100 rounded-xl shadow-lg border border-slate-950 p-5 flex flex-col h-[520px]">
        <div className="flex items-center justify-between mb-4 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4.5 h-4.5 text-indigo-400 shrink-0" />
            <h3 className="text-xs font-extrabold tracking-widest text-slate-300 uppercase">PDP: Trust Ledger</h3>
          </div>
          <button onClick={onRefresh} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        <p className="text-[11px] text-slate-400 mb-3 leading-normal">
          Log of continuous trust score fluctuations triggered by context, devices, and behavior signals.
        </p>

        {/* List of score changes */}
        <div className="flex-1 overflow-y-auto space-y-2 pr-1 font-mono text-[11px]">
          {trustLogs.map((log) => (
            <div key={log.id} className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/50 hover:border-slate-700/80 transition-all">
              <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                <span>ID: {log.id}</span>
              </div>
              <div className="flex items-center justify-between font-bold">
                <span className="text-slate-300">{log.eventType}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${log.trustChangeValue > 0 ? "bg-emerald-500/10 text-emerald-400" : (log.trustChangeValue < 0 ? "bg-rose-500/10 text-rose-400" : "bg-slate-700/20 text-slate-400")}`}>
                  {log.trustChangeValue > 0 ? `+${log.trustChangeValue}` : log.trustChangeValue}
                </span>
              </div>
              <div className="flex justify-between items-center text-[10px] text-slate-400 mt-2 border-t border-slate-800/80 pt-1.5">
                <span>Resulting Trust Score:</span>
                <span className={`font-bold ${log.resultingTrustScore >= 80 ? "text-emerald-400" : (log.resultingTrustScore >= 50 ? "text-amber-400" : (log.resultingTrustScore >= 25 ? "text-orange-400" : "text-rose-500"))}`}>
                  {log.resultingTrustScore}/100
                </span>
              </div>
            </div>
          ))}
          {trustLogs.length === 0 && (
            <div className="text-center text-slate-500 text-xs py-16 font-mono">
              Awaiting session lifecycle signals...
            </div>
          )}
        </div>
      </div>

      {/* PEP Forensic Audit Trail Column */}
      <div className="lg:col-span-7 bg-white rounded-xl shadow-xs border border-slate-200 p-5 flex flex-col h-[520px]">
        <div className="flex items-center justify-between mb-4 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <FileText className="w-4.5 h-4.5 text-slate-800 shrink-0" />
            <h3 className="text-sm font-bold text-slate-800 tracking-tight">PEP: Forensic Audit Log</h3>
          </div>
          <button onClick={onRefresh} className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-50 transition-colors cursor-pointer">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Filter Toolbar */}
        <div className="flex flex-col sm:flex-row gap-2.5 mb-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search actor, role, action..."
              value={auditSearch}
              onChange={(e) => setAuditSearch(e.target.value)}
              className="w-full pl-8.5 pr-3 py-1.5 bg-slate-50/50 border border-slate-250 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 focus:outline-none focus:border-indigo-500 text-slate-800"
            />
          </div>
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            className="border border-slate-250 bg-slate-50/50 rounded-lg py-1.5 px-3 text-xs focus:ring-1 focus:ring-indigo-500 text-slate-700 font-bold cursor-pointer"
          >
            <option value="all">All Decisions</option>
            <option value="ALLOWED">ALLOWED</option>
            <option value="DENIED">DENIED</option>
            <option value="STEP-UP OTP">STEP-UP OTP</option>
            <option value="TERMINATED">TERMINATED</option>
          </select>
        </div>

        {/* Audit list scrollable */}
        <div className="flex-1 overflow-y-auto space-y-2.5 pr-1 font-mono text-[11px]">
          {filteredAudits.map((audit) => (
            <div key={audit.id} className="p-3 border border-slate-200/85 rounded-lg hover:bg-slate-50/50 transition-all">
              <div className="flex items-start justify-between gap-4 mb-2">
                <div>
                  <span className="font-sans text-xs font-bold text-slate-800">{audit.userName}</span>
                  <span className="font-sans text-[9px] font-bold text-indigo-600 bg-indigo-50/60 border border-indigo-100 rounded px-1.5 py-0.5 ml-2 uppercase">
                    {audit.role.replace("Administrative ", "")}
                  </span>
                  {audit.riskLevel && (
                    <span className={`font-sans text-[9px] font-bold rounded px-1.5 py-0.5 ml-1.5 uppercase ${
                      audit.riskLevel === "CRITICAL" ? "bg-rose-100 text-rose-800 border border-rose-200" :
                      audit.riskLevel === "HIGH RISK" ? "bg-orange-100 text-orange-800 border border-orange-200" :
                      audit.riskLevel === "SUSPICIOUS" ? "bg-amber-100 text-amber-800 border border-amber-200" :
                      "bg-emerald-100 text-emerald-800 border border-emerald-200"
                    }`}>
                      {audit.riskLevel}
                    </span>
                  )}
                  {audit.emailAlertSent && (
                    <span className="inline-flex items-center gap-1 font-sans text-[9px] font-bold text-sky-700 bg-sky-50 border border-sky-200 rounded px-1.5 py-0.5 ml-1.5">
                      <Mail className="w-2.5 h-2.5 text-sky-600" />
                      Alert Sent
                    </span>
                  )}
                </div>
                <span className={`inline-block font-sans text-[9px] font-bold tracking-wider px-2 py-0.5 rounded border ${
                  audit.decision === "ALLOWED" ? "bg-emerald-50 text-emerald-700 border-emerald-200/50" :
                  audit.decision === "DENIED" ? "bg-amber-50 text-amber-700 border-amber-200/50" :
                  audit.decision === "STEP-UP OTP" ? "bg-orange-50 text-orange-700 border-orange-200/50" :
                  "bg-rose-50 text-rose-700 border-rose-200/50"
                }`}>
                  {audit.decision}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-slate-600 mt-2 border-t border-slate-100/70 pt-2 pb-1">
                <div>
                  <span className="text-[9px] text-slate-400 block uppercase tracking-widest font-sans font-bold">Action</span>
                  <span className="font-bold text-slate-800 font-mono text-[11px]">{audit.actionPerformed}</span>
                </div>
                <div>
                  <span className="text-[9px] text-slate-400 block uppercase tracking-widest font-sans font-bold">Resource Node</span>
                  <span className="text-slate-700 font-mono text-[11px]">{audit.resourceAccessed}</span>
                </div>
              </div>

              {audit.reasons && audit.reasons.length > 0 && (
                <div className="mt-1.5 bg-amber-50/50 border border-amber-200/50 rounded p-1.5 text-[10px] text-amber-900 font-sans">
                  <span className="font-bold text-[9px] uppercase tracking-wider text-amber-700 block mb-0.5">Threat Signals:</span>
                  <ul className="list-disc list-inside space-y-0.5">
                    {audit.reasons.slice(0, 3).map((r, idx) => (
                      <li key={idx} className="truncate">{r}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="flex justify-between items-center text-[10px] text-slate-400 border-t border-slate-100 pt-1.5 mt-2">
                <span>Trust Score: <b>{audit.trustScoreAtAction}/100</b> {audit.previousTrustScore !== undefined && audit.previousTrustScore !== audit.trustScoreAtAction && <span className="text-[9px] text-slate-400">(was {audit.previousTrustScore})</span>}</span>
                <span>{new Date(audit.timestamp).toLocaleTimeString()}</span>
              </div>
            </div>
          ))}
          {filteredAudits.length === 0 && (
            <div className="text-center text-slate-400 text-xs py-16">
              No audit logs captured matching query parameters.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
