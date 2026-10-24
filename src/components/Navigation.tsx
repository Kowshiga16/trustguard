/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { ShieldCheck, UserCheck, LogOut, KeyRound } from "lucide-react";
import { ActiveSession, RoleName } from "../types";

interface NavigationProps {
  session: ActiveSession | null;
  onLogout: () => void;
  onRequestOtp?: () => Promise<void>;
}

export default function Navigation({
  session,
  onLogout,
  onRequestOtp
}: NavigationProps) {

  return (
    <nav className="h-16 bg-white border-b border-slate-200 px-3 sm:px-6 flex items-center justify-between shadow-xs sticky top-0 z-45 shrink-0 w-full max-w-full overflow-hidden">
      {/* Brand Logo */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        <div className="w-8 h-8 bg-indigo-700 rounded flex items-center justify-center text-white font-bold shadow-sm shrink-0">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
        </div>
        <div>
          <h1 className="text-sm sm:text-base md:text-lg font-bold tracking-tight text-slate-800 flex items-center gap-1.5 sm:gap-2">
            TrustGuard 
            <span className="font-normal text-slate-400 ml-1 border-l border-slate-200 pl-2 text-xs uppercase tracking-widest hidden md:inline-block">
              Revenue Dept
            </span>
          </h1>
        </div>
      </div>

      {/* Profile / Switch Role Selector */}
      <div className="flex items-center gap-2 sm:gap-3 relative shrink-0">
        {session ? (
          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            <div className="text-right hidden sm:block">
              <span className="block text-xs font-bold text-slate-800 leading-tight">{session.userName}</span>
              <span className="text-[11px] font-semibold text-indigo-700 font-mono hidden lg:block leading-tight">{session.userEmail || "officer@revenue.tn.gov.in"}</span>
              <div className="flex items-center justify-end gap-1.5 mt-0.5">
                <span className="inline-flex items-center gap-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                  Role: <b className="text-indigo-600 uppercase tracking-wider font-extrabold">{session.role.replace("Administrative ", "")}</b>
                </span>
                {session.role === RoleName.SystemAdministrator && (
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-black uppercase tracking-wider bg-purple-100 text-purple-800 border border-purple-200">
                    Root Admin
                  </span>
                )}
                {session.role === RoleName.DataEntryOperator && (
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-black uppercase tracking-wider bg-emerald-100 text-emerald-800 border border-emerald-200">
                    DEO Mode
                  </span>
                )}
              </div>
            </div>

            {/* Step-Up OTP Verification Trigger */}
            {onRequestOtp && (
              <button
                onClick={onRequestOtp}
                title="Trigger Step-Up OTP Challenge"
                className="flex items-center gap-1.5 bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 py-1.5 px-2 sm:px-3 rounded-lg text-xs font-bold transition-all cursor-pointer shadow-2xs shrink-0 whitespace-nowrap"
              >
                <KeyRound className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                <span className="hidden sm:inline">Verify via OTP</span>
                <span className="inline sm:hidden">OTP</span>
              </button>
            )}

            {/* Real-time IP & Network Route Indicator (visible on xl+ to prevent navbar squeeze) */}
            <div className="hidden xl:flex flex-col items-end px-3 py-1 bg-slate-50 border border-slate-200 rounded-lg text-[10px] font-mono shrink-0">
              <div className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${session.simulatedIpMismatch ? "bg-rose-500 animate-ping" : "bg-emerald-500"}`}></span>
                <span className="text-slate-500 font-bold font-sans">IP:</span>
                <span className="font-bold text-slate-800">{session.currentRequestIp || session.ipAddress}</span>
              </div>
              <div className="text-[9px] text-slate-400 font-sans">
                {session.simulatedIpMismatch ? (
                  <span className="text-rose-600 font-bold">Route Shift (-20 pts)</span>
                ) : (
                  <span className="text-emerald-700 font-semibold">Route Verified</span>
                )}
              </div>
            </div>

            <div className="relative shrink-0">
              <div className={`flex items-center gap-1.5 sm:gap-2 border py-1.5 px-2.5 sm:px-3 rounded-lg text-xs font-bold shrink-0 whitespace-nowrap ${
                session.role === RoleName.SystemAdministrator
                  ? "bg-purple-50/80 border-purple-200 text-purple-900 shadow-2xs"
                  : session.role === RoleName.DataEntryOperator
                  ? "bg-emerald-50/80 border-emerald-200 text-emerald-900 shadow-2xs"
                  : "bg-slate-50 border-slate-200 text-slate-700"
              }`}>
                <UserCheck className={`w-4 h-4 shrink-0 ${
                  session.role === RoleName.SystemAdministrator
                    ? "text-purple-600"
                    : session.role === RoleName.DataEntryOperator
                    ? "text-emerald-600"
                    : "text-indigo-600"
                }`} />
                <span className="hidden md:inline">
                  {session.role === RoleName.SystemAdministrator ? "Admin Console" : session.role === RoleName.DataEntryOperator ? "Operator Mode" : "Signed In"}
                </span>
                <span className="inline md:hidden">Identity</span>
              </div>
            </div>

            {/* Logout control */}
            <button
              onClick={onLogout}
              title="Terminate Session"
              className="p-2 border border-slate-200 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-50 transition-all cursor-pointer shrink-0"
            >
              <LogOut className="w-4 h-4 text-rose-500" />
            </button>
          </div>
        ) : (
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Authentication Required</span>
        )}
      </div>
    </nav>
  );
}
