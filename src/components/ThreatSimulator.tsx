/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { AlertOctagon, ShieldAlert, Sparkles, RefreshCw, AlertTriangle, Play, HelpCircle, UserX, Clock, MapPin, Laptop, Wifi, Mail, KeyRound } from "lucide-react";
import { ActiveSession } from "../types";

interface ThreatSimulatorProps {
  session: ActiveSession | null;
  onToggleParam: (param: string, value: boolean) => void;
  onTriggerSpam: () => void;
  onTriggerRoleOtpSimulation?: () => Promise<void>;
  onClearPenalties: () => void;
}

export default function ThreatSimulator({
  session,
  onToggleParam,
  onTriggerSpam,
  onTriggerRoleOtpSimulation,
  onClearPenalties
}: ThreatSimulatorProps) {
  if (!session) return null;

  const [simulatingOtp, setSimulatingOtp] = useState(false);

  const getRoleThreshold = (roleName: string) => {
    const norm = (roleName || "").toLowerCase();
    if (norm.includes("admin")) return 70;
    if (norm.includes("tahsildar") && !norm.includes("deputy")) return 70;
    if (norm.includes("deputy")) return 65;
    if (norm.includes("citizen")) return 50;
    return 60;
  };

  const roleThreshold = getRoleThreshold(session.role);

  const threats = [
    {
      id: "simulatedDeviceMismatch",
      name: "Device Fingerprint Mismatch",
      desc: "Hijacked login cookie transferred to another machine.",
      penalty: -20,
      icon: Laptop,
      active: session.simulatedDeviceMismatch
    },
    {
      id: "simulatedIpMismatch",
      name: "Mid-Session IP Route Drift",
      desc: "User shifts networks mid-session or hops onto a proxy/VPN.",
      penalty: -15,
      icon: Wifi,
      active: session.simulatedIpMismatch
    },
    {
      id: "simulatedNightAccess",
      name: "Off-Hours Night Access",
      desc: "Simulates access outside typical working hours (e.g., 2:00 AM).",
      penalty: -10,
      icon: Clock,
      active: session.simulatedNightAccess
    },
    {
      id: "simulatedOutsideJurisdiction",
      name: "Cross-Jurisdiction Access Attempt",
      desc: "Officer requests land records outside assigned taluk/village.",
      penalty: -20,
      icon: MapPin,
      active: session.simulatedOutsideJurisdiction
    },
    {
      id: "simulatedIdleTriggered",
      name: "Post-Idle Burst Trigger",
      desc: "Session goes completely idle, then immediately submits a record.",
      penalty: -10,
      icon: Clock,
      active: session.simulatedIdleTriggered
    }
  ];

  return (
    <div id="threat-simulator-panel" className="bg-slate-900 text-white rounded-xl shadow-lg border border-slate-950 p-6 flex flex-col h-full overflow-hidden">
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="bg-red-500/15 p-1.5 rounded-lg border border-red-500/30">
            <ShieldAlert className="w-5 h-5 text-red-400" />
          </div>
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-200">Threat Simulator</h3>
        </div>
        <button
          onClick={onClearPenalties}
          className="flex items-center gap-1.5 text-[11px] font-bold text-sky-400 hover:text-sky-300 transition-colors bg-slate-800 hover:bg-slate-750 px-3 py-1.5 rounded-lg border border-slate-700 cursor-pointer"
        >
          <RefreshCw className="w-3 h-3" />
          Reset State
        </button>
      </div>

      <p className="text-xs text-slate-400 mb-5 leading-relaxed">
        Toggle simulated security events in real-time. Watch how the <b>Policy Decision Point (PDP)</b> instantly recalculates the session trust score, and the <b>Policy Enforcement Point (PEP)</b> dynamically restricts the UI.
      </p>

      {/* Threats grid */}
      <div className="space-y-3 flex-1 overflow-y-auto pr-1">
        {threats.map((threat) => {
          const ThreatIcon = threat.icon;
          return (
            <div
              key={threat.id}
              className={`p-3.5 rounded-lg border transition-all flex items-start gap-3.5 ${
                threat.active
                  ? "bg-red-950/20 border-red-500/40"
                  : "bg-slate-800/30 border-slate-800 hover:border-slate-750"
              }`}
            >
              <div className="pt-0.5 shrink-0">
                <div
                  className={`p-2 rounded-lg border ${
                    threat.active
                      ? "bg-red-500/10 border-red-500/20 text-red-400"
                      : "bg-slate-850 border-slate-800 text-slate-400"
                  }`}
                >
                  <ThreatIcon className="w-4 h-4" />
                </div>
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200 block truncate">{threat.name}</span>
                  <span className="text-[9px] font-extrabold text-rose-400 tracking-wider uppercase bg-rose-500/10 px-1.5 py-0.5 rounded ml-2">
                    {threat.penalty}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1 leading-normal pr-4">{threat.desc}</p>
              </div>

              <div className="relative inline-flex items-center shrink-0 pt-0.5">
                <input
                  type="checkbox"
                  id={`toggle-${threat.id}`}
                  checked={threat.active}
                  onChange={(e) => onToggleParam(threat.id, e.target.checked)}
                  className="sr-only peer cursor-pointer"
                />
                <div 
                  onClick={() => onToggleParam(threat.id, !threat.active)}
                  className="w-9 h-5 bg-slate-750 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[4px] after:left-[2px] after:bg-white after:border-slate-400 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-red-500 cursor-pointer"
                ></div>
              </div>
            </div>
          );
        })}

        {/* Special Spike Request Button */}
        <div className="p-3.5 bg-slate-800/30 border border-slate-800 rounded-lg flex items-start gap-3.5">
          <div className="pt-0.5 shrink-0">
            <div className={`p-2 rounded-lg border ${session.simulatedSpamTriggered ? "bg-red-500/10 border-red-500/20 text-red-400" : "bg-slate-850 border-slate-800 text-slate-400"}`}>
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200">Rapid Request Spike Attack</span>
              <span className="text-[9px] font-extrabold text-rose-400 tracking-wider uppercase bg-rose-500/10 px-1.5 py-0.5 rounded">
                -15
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1 leading-normal mb-3">
              Spam 25 access attempts within 5 seconds to simulate API hijacking.
            </p>
            <button
              onClick={onTriggerSpam}
              disabled={session.simulatedSpamTriggered}
              className={`w-full py-2 px-3 rounded-lg text-xs font-bold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                session.simulatedSpamTriggered
                  ? "bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed"
                  : "bg-red-600 hover:bg-red-500 text-white shadow-sm"
              }`}
            >
              <Play className="w-3.5 h-3.5" />
              {session.simulatedSpamTriggered ? "Spam Penalty Active" : "Trigger Spam Simulation"}
            </button>
          </div>
        </div>

        {/* Role-Based Low-Trust Simulation & NodeMailer OTP Trigger */}
        <div className="p-3.5 bg-indigo-950/30 border border-indigo-500/30 rounded-lg flex items-start gap-3.5">
          <div className="pt-0.5 shrink-0">
            <div className="p-2 rounded-lg border bg-indigo-500/10 border-indigo-500/30 text-indigo-400">
              <Mail className="w-4 h-4" />
            </div>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200">Role-Based Low Trust OTP Simulation</span>
              <span className="text-[9px] font-extrabold text-indigo-300 tracking-wider uppercase bg-indigo-500/20 px-1.5 py-0.5 rounded">
                Threshold: {roleThreshold}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1 leading-normal mb-3">
              Simulate low trust score for <b className="text-indigo-300">{session.role}</b> dropping below {roleThreshold}. Automatically triggers <b>NodeMailer OTP generation</b> & delivery to <b className="text-slate-300">{session.userEmail}</b>.
            </p>
            <button
              onClick={async () => {
                if (!onTriggerRoleOtpSimulation) return;
                setSimulatingOtp(true);
                try {
                  await onTriggerRoleOtpSimulation();
                } finally {
                  setSimulatingOtp(false);
                }
              }}
              disabled={simulatingOtp}
              className="w-full py-2 px-3 rounded-lg text-xs font-bold flex items-center justify-center gap-1.5 transition-all cursor-pointer bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed"
            >
              {simulatingOtp ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Generating NodeMailer OTP...
                </>
              ) : (
                <>
                  <KeyRound className="w-3.5 h-3.5" />
                  Simulate Low Trust & Trigger OTP
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      <div className="mt-5 border-t border-slate-800 pt-4 text-[10px] text-slate-400 flex items-center gap-2">
        <Sparkles className="w-4 h-4 text-amber-400 shrink-0" />
        <span>Tip: Try activating multiple threats to drop the trust score below 25!</span>
      </div>
    </div>
  );
}
