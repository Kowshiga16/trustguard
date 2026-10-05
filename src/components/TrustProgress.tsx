import React, { useEffect, useState } from "react";
import { Shield, ShieldAlert, ShieldCheck, ShieldAlert as Lock, HelpCircle, Brain, Activity } from "lucide-react";
import { ActiveSession } from "../types";

interface TrustProgressProps {
  session: ActiveSession | null;
  onSessionUpdate?: (updatedSession: ActiveSession) => void;
}

export default function TrustProgress({ session, onSessionUpdate }: TrustProgressProps) {
  const [hybridData, setHybridData] = useState<any>(null);

  useEffect(() => {
    if (!session?.id) return;
    const fetchHybridTrust = async () => {
      try {
        const res = await fetch("/api/security/hybrid-trust", {
          headers: { Authorization: session.id }
        });
        if (res.ok) {
          const data = await res.json();
          setHybridData(data);
          if (data.finalTrustScore !== undefined && data.finalTrustScore !== session.currentTrustScore) {
            onSessionUpdate?.({
              ...session,
              currentTrustScore: data.finalTrustScore,
              status: data.finalTrustScore < 40 ? "Blocked" : "Active"
            });
          }
        }
      } catch (err) {
        console.error("Failed to fetch hybrid trust", err);
      }
    };
    fetchHybridTrust();
    const interval = setInterval(fetchHybridTrust, 2500);
    return () => clearInterval(interval);
  }, [session?.id, session?.currentTrustScore]);

  if (!session) return null;

  const score = hybridData?.finalTrustScore !== undefined ? hybridData.finalTrustScore : session.currentTrustScore;

  // Phase 14 mappings
  let bandName = "Unknown";
  let bandColor = "bg-gray-200 text-gray-800";
  let bandDesc = "";
  let Icon = HelpCircle;
  let accessDecision = "UNKNOWN";

  if (score >= 80) {
    bandName = "Low Risk • Full Access";
    bandColor = "bg-emerald-950/30 text-emerald-300 border-emerald-900/40";
    bandDesc = "Optimal zero trust posture. Normal access, viewing certified records, creating mutations, approvals enabled. OTP not required.";
    Icon = ShieldCheck;
    accessDecision = "FULL";
  } else if (score >= 60) {
    bandName = "Medium Risk • Restricted";
    bandColor = "bg-amber-950/30 text-amber-300 border-amber-900/40";
    bandDesc = "Moderate risk or contextual drift. Permitted records viewable. Step-Up OTP required for sensitive mutations and approvals.";
    Icon = Shield;
    accessDecision = "RESTRICTED";
  } else if (score >= 40) {
    bandName = "High Risk • Read-Only";
    bandColor = "bg-orange-950/30 text-orange-300 border-orange-900/40";
    bandDesc = "Elevated risk detected. Permitted records viewable in Read-Only mode. Mutations and approvals blocked. Step-Up OTP required to restore privileges.";
    Icon = ShieldAlert;
    accessDecision = "READ-ONLY";
  } else {
    bandName = "Critical Risk • Blocked";
    bandColor = "bg-rose-950/30 text-rose-300 border-rose-900/40";
    bandDesc = "Severe anomaly or multiple security violations. Access blocked. Session challenged / terminated.";
    Icon = Lock;
    accessDecision = "BLOCKED";
  }

  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div id="trust-progress-panel" className="bg-slate-900 text-white rounded-xl shadow-lg border border-slate-950 flex flex-col h-full overflow-hidden">
      <div className="p-4 bg-slate-800 flex items-center justify-between border-b border-slate-950">
        <h3 className="text-xs font-bold uppercase tracking-widest text-slate-200 flex items-center gap-2">
          <Shield className="w-4 h-4 text-indigo-400" />
          Hybrid Trust Engine
        </h3>
        <span className="text-[10px] text-indigo-400 font-mono uppercase tracking-tight">Access: {accessDecision}</span>
      </div>

      <div className="p-4 flex-1 flex flex-col gap-4 overflow-y-auto">
        <div className="flex items-center gap-4">
          <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
            <svg className="w-full h-full transform -rotate-90">
              <circle cx="48" cy="48" r={radius} className="stroke-slate-800" strokeWidth="6" fill="transparent" />
              <circle
                cx="48" cy="48" r={radius}
                strokeDasharray={circumference}
                strokeDashoffset={offset}
                strokeLinecap="round"
                className={`transition-all duration-500 ${score >= 80 ? "stroke-emerald-500" : score >= 60 ? "stroke-amber-500" : score >= 40 ? "stroke-orange-500" : "stroke-rose-500"}`}
                strokeWidth="6" fill="transparent"
              />
            </svg>
            <div className="absolute text-center">
              <span className="block text-2xl font-extrabold text-white tracking-tight">{score}</span>
              <span className="text-[8px] font-bold text-slate-500 uppercase tracking-wider block">FINAL TRUST</span>
            </div>
          </div>
          <div className="flex-1 space-y-2">
            <div className={`p-2.5 rounded-lg border flex items-start gap-2 ${bandColor}`}>
              <Icon className="w-4 h-4 shrink-0 mt-0.5 text-inherit" />
              <div>
                <h4 className="text-[10px] font-bold uppercase tracking-wider">{bandName}</h4>
                <p className="text-[10px] mt-0.5 leading-snug text-slate-300 font-medium">{bandDesc}</p>
              </div>
            </div>
            {hybridData && (
              <div className="text-[9px] text-slate-400 flex flex-wrap gap-x-3 gap-y-1 font-semibold tracking-wide uppercase px-0.5">
                <span>ML Status: <b className={`font-mono ${hybridData.mlServiceStatus === "AVAILABLE" ? "text-emerald-400" : "text-rose-400"}`}>{hybridData.mlServiceStatus}</b></span>
                <span>NAS: <b className="font-mono text-slate-200">{hybridData.normalizedAnomalyScore?.toFixed(2)}</b></span>
              </div>
            )}
          </div>
        </div>

        {/* Phase 17: Hybrid Breakdown Dashboard */}
        <div className="grid grid-cols-2 gap-3 mt-2">
           <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-800">
              <div className="flex items-center gap-1.5 text-[10px] font-bold text-slate-400 uppercase mb-1">
                 <ShieldAlert className="w-3.5 h-3.5 text-indigo-400" /> RULE-BASED RISK
              </div>
              <div className="text-xl font-mono font-bold text-white">{hybridData ? Math.round(hybridData.ruleRisk) : 100 - session.currentTrustScore} <span className="text-xs text-slate-500 font-sans font-normal">pts</span></div>
           </div>
           <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-800">
              <div className="flex items-center gap-1.5 text-[10px] font-bold text-slate-400 uppercase mb-1">
                 <Brain className="w-3.5 h-3.5 text-purple-400" /> ML ANOMALY RISK
              </div>
              <div className="text-xl font-mono font-bold text-white">{hybridData ? Math.round(hybridData.mlRisk) : 0} <span className="text-xs text-slate-500 font-sans font-normal">pts</span></div>
           </div>
        </div>

        {/* Explainable Factor Breakdown */}
        {hybridData?.riskFactors && Object.keys(hybridData.riskFactors).length > 0 && (
          <div className="bg-slate-850/80 rounded-lg p-2.5 border border-slate-800">
            <h5 className="text-[9px] font-bold uppercase tracking-wider text-rose-400 mb-1.5 flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-rose-400" /> Explainable Risk Factors
            </h5>
            <div className="space-y-1">
              {Object.entries(hybridData.riskFactors).map(([factor, pts]: [string, any]) => (
                <div key={factor} className="flex justify-between items-center text-[10px] text-slate-300">
                  <span className="truncate pr-2">{factor}</span>
                  <span className="font-mono font-bold text-rose-400 shrink-0">-{pts} pts</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {/* Real-time IP & Network Route Shift Telemetry */}
        <div className="bg-slate-850/80 rounded-lg p-3 border border-slate-800 text-[10px] space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-indigo-400" /> Network Route Telemetry
            </span>
            <span className={`px-2 py-0.5 rounded font-bold text-[9px] ${
              session.simulatedIpMismatch 
                ? "bg-rose-500/20 text-rose-300 border border-rose-500/40" 
                : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
            }`}>
              {session.simulatedIpMismatch ? "Route Shift: -15 pts" : "Verified: Match (0 pts)"}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 font-mono text-[10px]">
            <div className="bg-slate-900/60 p-2 rounded border border-slate-800">
              <span className="text-slate-500 block text-[9px] font-sans">Initial Authenticated IP:</span>
              <span className="text-slate-200 font-bold truncate block">{session.realLoginIp || session.initialAuthenticatedIp || session.ipAddress}</span>
            </div>
            <div className="bg-slate-900/60 p-2 rounded border border-slate-800">
              <span className="text-slate-500 block text-[9px] font-sans">Current Observed IP:</span>
              <span className={`font-bold truncate block ${session.simulatedIpMismatch ? "text-rose-400 font-bold" : "text-emerald-400"}`}>
                {session.currentRequestIp || session.ipAddress}
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between pt-1 border-t border-slate-800/80">
            <span className="text-slate-400 text-[9px]">Criterion 2: IP Address / Route Hop</span>
            <button
              onClick={async () => {
                try {
                  const res = await fetch("/api/simulation/toggle", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      sessionId: session.id,
                      param: "simulatedIpMismatch",
                      value: !session.simulatedIpMismatch
                    })
                  });
                  if (res.ok) {
                    const fresh = await res.json();
                    onSessionUpdate?.(fresh);
                  }
                } catch (e) {}
              }}
              className={`px-2.5 py-1 rounded text-[10px] font-bold transition-all cursor-pointer ${
                session.simulatedIpMismatch
                  ? "bg-emerald-950/60 text-emerald-300 border border-emerald-700/50 hover:bg-emerald-900"
                  : "bg-rose-950/60 text-rose-300 border border-rose-700/50 hover:bg-rose-900"
              }`}
            >
              {session.simulatedIpMismatch ? "↺ Restore Original IP Route" : "⚡ Test IP Route Shift (-15 pts)"}
            </button>
          </div>
        </div>

        <div className="border-t border-slate-800 pt-3 flex-1 mt-1">
          <h4 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">Current Behavioral Indicators</h4>
          {hybridData?.featuresUsed ? (
            <div className="grid grid-cols-2 gap-2">
               <div className="flex justify-between items-center text-[10px] py-1.5 px-2 bg-slate-800/40 rounded border border-slate-800">
                  <span className="text-slate-400">Req / Min</span>
                  <span className="font-mono font-bold text-emerald-400">{hybridData.featuresUsed.requests_per_minute}</span>
               </div>
               <div className="flex justify-between items-center text-[10px] py-1.5 px-2 bg-slate-800/40 rounded border border-slate-800">
                  <span className="text-slate-400">Records Viewed</span>
                  <span className="font-mono font-bold text-emerald-400">{hybridData.featuresUsed.records_viewed}</span>
               </div>
               <div className="flex justify-between items-center text-[10px] py-1.5 px-2 bg-slate-800/40 rounded border border-slate-800">
                  <span className="text-slate-400">Downloads</span>
                  <span className="font-mono font-bold text-emerald-400">{hybridData.featuresUsed.downloads_count}</span>
               </div>
               <div className="flex justify-between items-center text-[10px] py-1.5 px-2 bg-slate-800/40 rounded border border-slate-800">
                  <span className="text-slate-400">Failed Ops</span>
                  <span className="font-mono font-bold text-emerald-400">{hybridData.featuresUsed.failed_operations}</span>
               </div>
            </div>
          ) : (
            <div className="text-center text-[10px] text-slate-500 py-3">Monitoring behavioral signals...</div>
          )}
        </div>
      </div>
    </div>
  );
}
