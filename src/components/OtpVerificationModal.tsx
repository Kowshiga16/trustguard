/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from "react";
import { ShieldAlert, Key, ArrowRight, Loader, Mail, RefreshCw, CheckCircle2, AlertCircle } from "lucide-react";
import { ActiveSession } from "../types";

interface OtpVerificationModalProps {
  session: ActiveSession | null;
  onRequestOtp: () => Promise<void>;
  onVerifyOtp: (otp: string) => Promise<boolean>;
  onLogout: () => void;
}

function getRoleThreshold(roleName?: string): number {
  const norm = (roleName || "").toLowerCase();
  if (norm.includes("admin")) return 70;
  if (norm.includes("tahsildar") && !norm.includes("deputy")) return 70;
  if (norm.includes("deputy")) return 65;
  if (norm.includes("citizen")) return 50;
  return 60;
}

export default function OtpVerificationModal({
  session,
  onRequestOtp,
  onVerifyOtp,
  onLogout
}: OtpVerificationModalProps) {
  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [resendSuccess, setResendSuccess] = useState(false);
  const [success, setSuccess] = useState(false);

  const roleThreshold = getRoleThreshold(session?.role);

  const isOtpNeeded = Boolean(
    session &&
    !session.otpVerified &&
    (session.currentTrustScore <= roleThreshold || session.status === "Blocked" || (session as any).requiresOtp)
  );

  useEffect(() => {
    if (isOtpNeeded) {
      setOtp("");
      setErrorMsg("");
      setSuccess(false);
      setResendSuccess(false);
      void onRequestOtp();
    }
  }, [session?.id, session?.currentTrustScore, session?.otpVerified, isOtpNeeded]);

  if (!isOtpNeeded) {
    return null;
  }

  const handleResend = async () => {
    setResending(true);
    setErrorMsg("");
    setResendSuccess(false);
    try {
      await onRequestOtp();
      setResendSuccess(true);
      setTimeout(() => setResendSuccess(false), 4000);
    } catch (err: any) {
      setErrorMsg("Failed to resend OTP. Please try again.");
    } finally {
      setResending(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otp.trim()) return;

    setLoading(true);
    setErrorMsg("");

    try {
      const isOk = await onVerifyOtp(otp.trim());
      if (isOk) {
        setSuccess(true);
      } else {
        setErrorMsg("Verification failed. Please enter the correct 6-digit code received in your email.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "An error occurred during verification.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-[110] flex items-center justify-center p-4">
      <div className="bg-white rounded-xl max-w-md w-full shadow-2xl border border-slate-200 overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        
        {/* Warning Header */}
        <div className="bg-slate-900 text-white p-5 flex items-center justify-between border-b border-slate-950">
          <div className="flex items-center gap-3">
            <div className="bg-amber-500/15 p-2 rounded-lg border border-amber-500/30 shrink-0">
              <ShieldAlert className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold tracking-tight">Step-Up Identity Verification</h3>
              <p className="text-[10px] text-slate-400 mt-0.5 font-bold uppercase tracking-wider">
                Zero Trust PEP &bull; Low Trust Score Challenge
              </p>
            </div>
          </div>
          <span className="px-2.5 py-1 rounded-md bg-indigo-950 border border-indigo-700/50 text-[10px] font-extrabold text-indigo-300 uppercase">
            {session.role}
          </span>
        </div>

        {/* Content Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div className="text-slate-600 text-xs leading-relaxed space-y-3">
            <div className="p-3 bg-amber-50 border border-amber-200/80 rounded-lg text-amber-900 text-xs">
              <div className="flex items-center gap-1.5 font-bold mb-1">
                <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
                <span>Low Trust Threshold Triggered</span>
              </div>
              Your current trust score is <b className="text-amber-950 font-black">{session.currentTrustScore}/100</b>, which has dropped below the baseline of <b className="text-amber-950 font-black">{roleThreshold}/100</b> for the <b className="text-amber-950 font-black">{session.role}</b> role.
            </div>

            {/* Email dispatch confirmation banner */}
            <div className="bg-indigo-50/80 border border-indigo-100 p-3.5 rounded-lg flex items-start gap-2.5 text-xs text-indigo-950">
              <Mail className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="font-bold text-indigo-950 block">Real-Time Verification Code Dispatched:</span>
                <p className="text-slate-600 leading-normal">
                  A 6-digit one-time passcode has been sent to your verified email:
                  <b className="font-mono text-indigo-900 block mt-0.5 break-all">{session.userEmail || session.userName}</b>
                </p>
                <p className="text-[11px] text-slate-500 italic mt-1">
                  Please open your Gmail inbox (or spam folder) and enter the received code below.
                </p>
              </div>
            </div>
          </div>

          {resendSuccess && (
            <div className="text-xs text-indigo-700 bg-indigo-50 p-2.5 rounded-lg border border-indigo-200 font-bold flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-indigo-600 shrink-0" />
              <span>A fresh OTP has been dispatched to your email!</span>
            </div>
          )}

          {errorMsg && (
            <div className="text-xs text-rose-600 bg-rose-50 p-3 rounded-lg border border-rose-100 font-bold leading-relaxed flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {success && (
            <div className="text-xs text-emerald-700 bg-emerald-50 p-3 rounded-lg border border-emerald-200 font-bold leading-relaxed flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
              <span>OTP Verified successfully! Restoring session privileges...</span>
            </div>
          )}

          {/* OTP Code Input */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label htmlFor="otp-input" className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                Enter 6-Digit Email Code
              </label>
              <button
                type="button"
                onClick={handleResend}
                disabled={resending || loading}
                className="text-[10px] font-bold text-indigo-600 hover:text-indigo-500 flex items-center gap-1 cursor-pointer disabled:text-slate-400"
              >
                <RefreshCw className={`w-3 h-3 ${resending ? "animate-spin" : ""}`} />
                {resending ? "Sending to email..." : "Resend to Email"}
              </button>
            </div>
            
            <div className="relative rounded-lg shadow-xs">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <Key className="h-4 w-4 text-slate-400" />
              </div>
              <input
                type="text"
                id="otp-input"
                name="otpCode"
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
                maxLength={6}
                placeholder="------"
                className="block w-full pl-10 pr-3 py-2.5 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-center tracking-[0.35em] text-xl font-bold placeholder:tracking-normal placeholder:font-sans placeholder:text-sm placeholder:font-semibold"
                autoFocus
                required
              />
            </div>
          </div>

          <div className="pt-2 flex gap-3 text-xs font-semibold">
            <button
              type="button"
              onClick={onLogout}
              className="flex-1 py-2 px-4 border border-slate-300 rounded-lg text-slate-600 hover:bg-slate-50 transition-all cursor-pointer text-center font-bold"
            >
              Sign Out
            </button>
            <button
              type="submit"
              disabled={loading || success || otp.trim().length !== 6}
              className="flex-1 py-2.5 px-4 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-bold shadow-sm shadow-indigo-100 transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:bg-slate-300 disabled:cursor-not-allowed"
            >
              {loading ? (
                <Loader className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  Verify OTP
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
