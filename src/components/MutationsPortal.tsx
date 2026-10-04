/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { CheckCircle2, AlertOctagon, XCircle, ArrowRight, ShieldAlert, Lock, Clock, HelpCircle, UserCheck } from "lucide-react";
import { MutationRequest, ActiveSession, RoleName } from "../types";

interface MutationsPortalProps {
  mutations: MutationRequest[];
  session: ActiveSession | null;
  onApprove: (id: string) => Promise<boolean>;
  onReject: (id: string, reason: string) => Promise<boolean>;
}

export default function MutationsPortal({
  mutations,
  session,
  onApprove,
  onReject
}: MutationsPortalProps) {
  const [rejectReason, setRejectReason] = useState("");
  const [activeRejectId, setActiveRejectId] = useState<string | null>(null);
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  if (!session) return null;

  const isReadOnly = session.currentTrustScore < 80;
  const isAdmin = session.role === RoleName.SystemAdministrator;

  const getRequiredRoleForStatus = (status: string) => {
    switch (status) {
      case "Pending VAO":
        return RoleName.VillageAdministrativeOfficer;
      case "Pending RI":
        return RoleName.RevenueInspector;
      case "Pending Deputy Tahsildar":
        return RoleName.DeputyTahsildar;
      case "Pending Tahsildar":
        return RoleName.Tahsildar;
      default:
        return null;
    }
  };

  const getStepNumber = (status: string) => {
    switch (status) {
      case "Pending VAO": return 1;
      case "Pending RI": return 2;
      case "Pending Deputy Tahsildar": return 3;
      case "Pending Tahsildar": return 4;
      case "Approved": return 5;
      case "Rejected": return -1;
      default: return 0;
    }
  };

  const handleApproveClick = async (mId: string) => {
    if (isReadOnly) return;
    setLoadingId(mId);
    setErrorMsg("");
    try {
      const ok = await onApprove(mId);
      if (!ok) {
        setErrorMsg("Failed to approve mutation request. Ensure your Trust Score is >= 80.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "An error occurred.");
    } finally {
      setLoadingId(null);
    }
  };

  const handleRejectSubmit = async (e: React.FormEvent, mId: string) => {
    e.preventDefault();
    if (!rejectReason.trim() || isReadOnly) return;

    setLoadingId(mId);
    setErrorMsg("");
    try {
      const ok = await onReject(mId, rejectReason);
      if (ok) {
        setActiveRejectId(null);
        setRejectReason("");
      } else {
        setErrorMsg("Failed to reject mutation. Ensure Trust Score is >= 80.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "An error occurred.");
    } finally {
      setLoadingId(null);
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-xs border border-slate-200 p-6 flex flex-col h-full">
      <div className="mb-6 pb-4 border-b border-slate-100">
        <h3 className="text-base font-bold text-slate-800 tracking-tight">Mutation Approval Desk</h3>
        <p className="text-xs text-slate-500 mt-0.5 font-medium">Deed Transfer Pipeline (Requires progressive officer-level vetting & high trust).</p>
      </div>

      {isReadOnly && !isAdmin && (
        <div className="mb-5 bg-amber-50/70 border border-amber-200/60 p-4 rounded-lg flex items-start gap-3">
          <ShieldAlert className="w-4.5 h-4.5 text-amber-600 shrink-0 mt-0.5" />
          <p className="text-xs text-amber-800 leading-relaxed font-medium">
            <b>Approval Operations Suspended:</b> Mutation authorization is a high-risk mutation event. Because your Trust Score is <b>{session.currentTrustScore}</b> (&lt; 80), the Dynamic Policy PEP has suspended your approval/rejection capabilities.
          </p>
        </div>
      )}

      {errorMsg && (
        <div className="mb-5 bg-rose-50 border border-rose-200 p-4 rounded-lg text-xs text-rose-700 font-bold leading-relaxed">
          {errorMsg}
        </div>
      )}

      {/* Mutation requests list */}
      <div className="flex-1 space-y-5 overflow-y-auto max-h-[500px] pr-1">
        {mutations.map((m) => {
          const currentStep = getStepNumber(m.status);
          const requiredRole = getRequiredRoleForStatus(m.status);
          
          // Check if currently logged in user is authorized to approve this phase.
          let canApproveThisPhase = session.role === requiredRole;
          if (m.status === "Pending Tahsildar" && session.role === RoleName.Tahsildar) {
            canApproveThisPhase = true;
          }

          return (
            <div key={m.id} className="border border-slate-200 rounded-xl p-6 hover:border-slate-300 transition-colors bg-slate-50/20">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4 border-b border-slate-100 pb-4">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-bold text-slate-500 bg-slate-100 border border-slate-200 px-2.5 py-0.5 rounded-md tracking-wider">
                    FILE #{m.id.toUpperCase()}
                  </span>
                  <span className="text-[10px] text-slate-400 font-bold font-mono uppercase">
                    Filed: {new Date(m.createdAt).toLocaleDateString()}
                  </span>
                </div>

                {/* Horizontal Stepper (VAO -> RI -> Deputy Tahsildar -> Tahsildar -> Approved) */}
                {currentStep !== -1 ? (
                  <div className="flex items-center gap-2 text-[10px] font-bold text-slate-400 uppercase tracking-wider bg-slate-100/50 border border-slate-150 px-2.5 py-1 rounded-lg">
                    <span className={currentStep >= 1 ? "text-emerald-600 font-extrabold" : ""}>VAO</span>
                    <ArrowRight className="w-3 h-3 text-slate-300" />
                    <span className={currentStep >= 2 ? "text-emerald-600 font-extrabold" : ""}>RI</span>
                    <ArrowRight className="w-3 h-3 text-slate-300" />
                    <span className={currentStep >= 3 ? "text-emerald-600 font-extrabold" : ""}>DT</span>
                    <ArrowRight className="w-3 h-3 text-slate-300" />
                    <span className={currentStep >= 4 ? "text-emerald-600 font-extrabold" : ""}>Tah</span>
                    <ArrowRight className="w-3 h-3 text-slate-300" />
                    <span className={currentStep >= 5 ? "text-emerald-600 font-extrabold" : ""}>Approved</span>
                  </div>
                ) : (
                  <span className="text-[10px] font-bold text-rose-600 bg-rose-50 border border-rose-100 px-2.5 py-0.5 rounded-lg uppercase tracking-wide">
                    File Rejected
                  </span>
                )}
              </div>

              {/* Grid content */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4 text-xs">
                <div>
                  <h5 className="font-bold text-slate-400 text-[10px] uppercase tracking-wider mb-1">Asset Detail</h5>
                  <p className="font-bold text-slate-800">Survey No: {m.surveyNumber}</p>
                  <p className="text-slate-500 font-medium">{m.villageName} Village</p>
                </div>
                <div>
                  <h5 className="font-bold text-slate-400 text-[10px] uppercase tracking-wider mb-1">Transfer Registry</h5>
                  <p className="text-slate-600 font-semibold">From: <b className="text-slate-800 font-bold">{m.currentOwner}</b></p>
                  <p className="text-emerald-600 font-semibold">To: <b className="text-emerald-700 font-bold">{m.proposedOwner}</b></p>
                </div>
                <div>
                  <h5 className="font-bold text-slate-400 text-[10px] uppercase tracking-wider mb-1">Approval Gate</h5>
                  <div className="flex items-center gap-1.5 font-bold">
                    <Clock className="w-3.5 h-3.5 text-amber-500" />
                    <span className={m.approved ? "text-emerald-700 font-black" : "text-amber-800 font-bold"}>{m.approved ? "Approved" : "Mutation Pending"}</span>
                  </div>
                  <span className="text-[10px] text-slate-400 font-semibold block mt-1 uppercase tracking-wide">
                    {m.approved ? "Escalated to RI" : "Awaiting VAO Approval"}
                  </span>
                </div>
                <div>
                  <h5 className="font-bold text-slate-400 text-[10px] uppercase tracking-wider mb-1">Current Status</h5>
                  <div className="flex items-center gap-1.5 font-bold">
                    <Clock className="w-3.5 h-3.5 text-amber-500" />
                    <span className="text-amber-800 font-bold">{m.status}</span>
                  </div>
                  {requiredRole && (
                    <span className="text-[10px] text-slate-400 font-semibold block mt-1 uppercase tracking-wide">
                      Assigned: <b className="text-indigo-600 font-extrabold">{requiredRole.replace("Administrative ", "")}</b>
                    </span>
                  )}
                </div>
              </div>

              {/* Remarks block */}
              <div className="bg-slate-50/70 p-3.5 rounded-lg border border-slate-100 mb-4">
                <span className="block text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1.5">Applicant Grounding & Proof Remarks</span>
                <p className="text-xs text-slate-600 whitespace-pre-line leading-relaxed font-medium">{m.remarks}</p>
              </div>

              {/* Action Buttons */}
              {currentStep !== 5 && currentStep !== -1 && (
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-t border-slate-100 pt-4 gap-4">
                  <div>
                    {canApproveThisPhase ? (
                      <span className="inline-flex items-center gap-1.5 text-xs text-emerald-700 bg-emerald-50 border border-emerald-150 py-1.5 px-3 rounded-lg font-bold">
                        <UserCheck className="w-4 h-4 text-emerald-600" />
                        Operational authority active
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-xs text-slate-400 bg-slate-50 border border-slate-200 py-1.5 px-3 rounded-lg font-bold uppercase tracking-wider text-[10px]">
                        <Lock className="w-3.5 h-3.5 text-slate-400" />
                        Awaiting desk: {requiredRole ? requiredRole.replace("Administrative ", "") : ""}
                      </span>
                    )}
                  </div>

                  <div className="flex gap-2">
                    {canApproveThisPhase && (
                      <>
                        <button
                          onClick={() => {
                            if (isReadOnly) return;
                            setActiveRejectId(m.id);
                            setRejectReason("");
                          }}
                          disabled={isReadOnly}
                          className={`px-3 py-2 border rounded-lg text-xs font-bold hover:bg-slate-50 transition-all cursor-pointer flex items-center gap-1.5 ${
                            isReadOnly ? "text-slate-400 cursor-not-allowed border-slate-200" : "text-rose-600 border-rose-200 hover:border-rose-300"
                          }`}
                        >
                          <XCircle className="w-3.5 h-3.5" />
                          Reject
                        </button>

                        <button
                          onClick={() => handleApproveClick(m.id)}
                          disabled={isReadOnly || loadingId === m.id}
                          className={`px-4 py-2 text-xs font-bold rounded-lg shadow-sm transition-all cursor-pointer flex items-center gap-1.5 ${
                            isReadOnly
                              ? "bg-slate-100 text-slate-400 border border-slate-200 cursor-not-allowed"
                              : "bg-indigo-600 hover:bg-indigo-700 text-white shadow-sm shadow-indigo-100"
                          }`}
                        >
                          {isReadOnly ? <Lock className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                          {m.status === "Pending Tahsildar" ? "Final Approval" : "Vouch & Escalate"}
                        </button>
                      </>
                    )}
                  </div>
                </div>
              )}

              {/* Reject popup form */}
              {activeRejectId === m.id && (
                <form onSubmit={(e) => handleRejectSubmit(e, m.id)} className="mt-4 border-t border-dashed border-slate-200 pt-4 space-y-3.5">
                  <div className="space-y-1.5">
                    <label className="block text-[10px] font-bold text-rose-700 uppercase tracking-widest">Provide Rejection Reason (Mandatory)</label>
                    <textarea
                      required
                      rows={2}
                      value={rejectReason}
                      onChange={(e) => setRejectReason(e.target.value)}
                      placeholder="Input legal, spatial or jurisdictional discrepancies identified..."
                      className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-rose-500 focus:outline-none text-slate-700"
                    />
                  </div>
                  <div className="flex justify-end gap-2 text-xs font-semibold">
                    <button
                      type="button"
                      onClick={() => setActiveRejectId(null)}
                      className="px-3 py-2 border border-slate-250 rounded-lg text-slate-600 hover:bg-slate-50 cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg shadow-sm font-bold cursor-pointer"
                    >
                      Confirm File Rejection
                    </button>
                  </div>
                </form>
              )}
            </div>
          );
        })}

        {mutations.length === 0 && (
          <div className="text-center py-16 text-slate-400 text-xs font-semibold">
            No active mutation files mapped to your jurisdictional boundary.
          </div>
        )}
      </div>
    </div>
  );
}
