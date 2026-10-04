/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { ShieldCheck, UserCheck, LogOut } from "lucide-react";
import { ActiveSession } from "../types";

interface NavigationProps {
  session: ActiveSession | null;
  onLogout: () => void;
}

export default function Navigation({
  session,
  onLogout
}: NavigationProps) {

  return (
    <nav className="h-16 bg-white border-b border-slate-200 px-6 flex items-center justify-between shadow-xs sticky top-0 z-45 shrink-0">
      {/* Brand Logo */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 bg-indigo-700 rounded flex items-center justify-center text-white font-bold shadow-sm">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
        </div>
        <div>
          <h1 className="text-base md:text-lg font-bold tracking-tight text-slate-800 flex items-center gap-2">
            TrustGuard 
            <span className="font-normal text-slate-400 ml-1 border-l border-slate-200 pl-2 text-xs uppercase tracking-widest hidden sm:inline-block">
              Revenue Department
            </span>
          </h1>
        </div>
      </div>

      {/* Profile / Switch Role Selector */}
      <div className="flex items-center gap-3 relative shrink-0">
        {session ? (
          <div className="flex items-center gap-4">
            <div className="text-right hidden sm:block">
              <span className="block text-xs font-bold text-slate-800">{session.userName}</span>
              <span className="inline-flex items-center gap-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                Role: <b className="text-indigo-600 uppercase tracking-wider font-extrabold">{session.role.replace("Administrative ", "")}</b>
              </span>
            </div>

            <div className="relative">
              <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 py-1.5 px-3.5 rounded-lg text-xs font-bold text-slate-700">
                <UserCheck className="w-4 h-4 text-indigo-600" />
                <span className="hidden md:inline">Signed In</span>
                <span className="inline md:hidden">Identity</span>
              </div>
            </div>

            {/* Logout control */}
            <button
              onClick={onLogout}
              title="Terminate Session"
              className="p-2 border border-slate-200 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-50 transition-all cursor-pointer"
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
