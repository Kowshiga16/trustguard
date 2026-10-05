/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useMemo, useState } from "react";
import { FileText, MapPin, ShieldCheck, Bell, User, ClipboardCheck, Landmark, FolderOpen, Upload, CheckCircle, XCircle, AlertCircle } from "lucide-react";
import { Application, ApplicationStatus, ActiveSession, LandRecord, RoleName, User as AppUser, Village } from "../types";

interface CitizenDashboardProps {
  session: ActiveSession;
  users: AppUser[];
  villages: Village[];
  records: LandRecord[];
  applications: Application[];
  onSubmitApplication: (payload: any) => Promise<boolean>;
  onSessionUpdate?: (updatedSession: ActiveSession) => void;
}

export default function CitizenDashboard({ session, users, villages, records, applications, onSubmitApplication, onSessionUpdate }: CitizenDashboardProps) {
  const user = users.find((u) => u.id === session.userId) || users.find((u) => u.name === session.userName) || null;
  const ownedRecords = useMemo(() => records.filter((r) => r.ownerName === session.userName), [records, session.userName]);
  const otherVillageRecords = useMemo(() => records.filter((r) => r.ownerName !== session.userName && r.villageName === "Mudichur"), [records, session.userName]);
  const recentApplications = useMemo(() => applications.filter((a) => a.applicantId === session.userId).slice(0, 5), [applications, session.userId]);
  const villageName = useMemo(() => {
    const vId = user?.assignedJurisdiction?.villageId;
    return villages.find((v) => v.id === vId)?.name || "Village";
  }, [user, villages]);

  const [form, setForm] = useState({
    landRecordId: ownedRecords[0]?.id || "",
    surveyNumber: ownedRecords[0]?.surveyNumber || "",
    applicationType: "Patta" as "Patta" | "Chitta" | "Land Transfer",
    reason: "",
    supportingDocumentReference: ""
  });

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [viewingDoc, setViewingDoc] = useState<any>(null);
  const [securityNotice, setSecurityNotice] = useState<{ message: string; type: "error" | "success" } | null>(null);
  const [inspectingDocId, setInspectingDocId] = useState<string | null>(null);

  const handleInspectDocument = async (recordId: string, ownerName: string) => {
    setInspectingDocId(recordId);
    setSecurityNotice(null);
    try {
      const res = await fetch(`/api/records/${recordId}/view`, {
        headers: { Authorization: session.id }
      });
      const data = await res.json();
      if (res.ok && data.authorized) {
        setViewingDoc(data.documentPayload);
        setSecurityNotice({
          message: `Zero Trust PEP Verified: Ownership confirmed. Certified land registry deed unlocked.`,
          type: "success"
        });
        if (data.evaluation?.trustScore !== undefined) {
          onSessionUpdate?.({ ...session, currentTrustScore: data.evaluation.trustScore });
        }
      } else {
        const penaltyMsg = data.trustScore !== undefined 
          ? `Access Denied by Policy Decision Point: You do not possess ownership authorization for this deed (Owner: ${ownerName}). Failed attempt logged: -10 pts penalty applied. Live Trust Score: ${data.trustScore}/100.`
          : (data.message || "Access Denied by Security Policy");
        setSecurityNotice({
          message: penaltyMsg,
          type: "error"
        });
        if (data.trustScore !== undefined) {
          onSessionUpdate?.({
            ...session,
            currentTrustScore: data.trustScore,
            failedActionCount: (session.failedActionCount || 0) + 1,
            status: data.trustScore < 40 ? "Blocked" : session.status
          });
        }
      }
    } catch (err: any) {
      setSecurityNotice({
        message: err.message || "Communication error with Zero Trust PDP Gateway.",
        type: "error"
      });
    } finally {
      setInspectingDocId(null);
    }
  };

  const submitApplication = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const payload = {
        landRecordId: form.landRecordId,
        surveyNumber: form.surveyNumber,
        applicationType: form.applicationType,
        reason: form.reason,
        supportingDocumentReference: form.supportingDocumentReference || undefined
      };

      const ok = await onSubmitApplication(payload);
      if (!ok) {
        setError("Unable to submit the application for the selected record.");
      } else {
        setForm({
          landRecordId: ownedRecords[0]?.id || "",
          surveyNumber: ownedRecords[0]?.surveyNumber || "",
          applicationType: "Patta",
          reason: "",
          supportingDocumentReference: ""
        });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="bg-white rounded-xl border border-slate-200 shadow-xs p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="text-[10px] font-extrabold uppercase tracking-widest text-indigo-600">Citizen Dashboard</div>
            <h2 className="text-xl font-black text-slate-800 mt-2">{session.userName}</h2>
            <div className="text-[11px] text-slate-500 font-bold mt-1">Citizen ID: {session.userId}</div>
          </div>
          <div className="flex flex-wrap gap-2">
            <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-100 text-[10px] font-black uppercase">
              <ShieldCheck className="w-3.5 h-3.5" /> Trust {session.currentTrustScore}/100
            </span>
            <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded-full bg-slate-50 text-slate-700 border border-slate-200 text-[10px] font-black uppercase">
              <ShieldCheck className="w-3.5 h-3.5" /> {session.status}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 mt-6">
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <div className="text-[9px] font-extrabold uppercase tracking-widest text-slate-500">District</div>
            <div className="text-sm font-black text-slate-800 mt-1">{user?.assignedJurisdiction?.district || "Kancheepuram"}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <div className="text-[9px] font-extrabold uppercase tracking-widest text-slate-500">Taluk</div>
            <div className="text-sm font-black text-slate-800 mt-1">{user?.assignedJurisdiction?.taluk || "Tambaram"}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <div className="text-[9px] font-extrabold uppercase tracking-widest text-slate-500">Village</div>
            <div className="text-sm font-black text-slate-800 mt-1">{villageName}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <div className="text-[9px] font-extrabold uppercase tracking-widest text-slate-500">Land Records</div>
            <div className="text-sm font-black text-slate-800 mt-1">{ownedRecords.length}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <div className="text-[9px] font-extrabold uppercase tracking-widest text-slate-500">Security Status</div>
            <div className="text-sm font-black text-slate-800 mt-1">{session.status}</div>
          </div>
        </div>
      </section>

      {securityNotice && (
        <div className={`p-4 rounded-xl border flex items-start gap-3 text-xs leading-relaxed font-bold animate-in fade-in duration-200 ${
          securityNotice.type === "success" 
            ? "bg-emerald-50 border-emerald-200 text-emerald-900" 
            : "bg-rose-50 border-rose-200 text-rose-900"
        }`}>
          {securityNotice.type === "success" ? (
            <CheckCircle className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
          ) : (
            <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
          )}
          <div className="flex-1">
            <span className="block font-black">{securityNotice.type === "success" ? "Zero Trust PDP Authorization:" : "Zero Trust Access Control Alert:"}</span>
            <p className="mt-0.5 font-medium">{securityNotice.message}</p>
          </div>
          <button onClick={() => setSecurityNotice(null)} className="text-slate-400 hover:text-slate-600 text-xs cursor-pointer">✕</button>
        </div>
      )}

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 space-y-6">
          <section className="bg-white rounded-xl border border-slate-200 shadow-xs p-5">
            <div className="flex justify-between items-center mb-4">
              <div className="flex items-center gap-2">
                <Landmark className="w-4 h-4 text-indigo-600" />
                <h3 className="text-sm font-black text-slate-800 uppercase tracking-wide">My Registered Land Records</h3>
              </div>
              <span className="text-[10px] font-bold text-slate-500">{ownedRecords.length} records</span>
            </div>
            <div className="grid gap-3">
              {ownedRecords.map((rec) => (
                <div key={rec.id} className="border border-slate-200 rounded-lg p-3 bg-slate-50/40">
                  <div className="flex justify-between items-center gap-3">
                    <div>
                      <div className="text-[10px] font-extrabold uppercase text-slate-500">Survey #{rec.surveyNumber}</div>
                      <div className="text-xs font-black text-slate-800 mt-1">{rec.villageName} / {rec.area}</div>
                      <span className="inline-block mt-1 text-[9px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded">Owner: {rec.ownerName} (Authorized)</span>
                    </div>
                    <div className="flex flex-wrap gap-2 items-center">
                      <button
                        onClick={() => handleInspectDocument(rec.id, rec.ownerName)}
                        disabled={inspectingDocId === rec.id}
                        className="text-[10px] font-black text-white bg-indigo-600 hover:bg-indigo-700 px-2.5 py-1.5 rounded transition-all cursor-pointer flex items-center gap-1 shadow-xs"
                      >
                        <FileText className="w-3 h-3" />
                        {inspectingDocId === rec.id ? "Verifying..." : "View Certified Deed"}
                      </button>
                      <a href={rec.pattaDocumentPath || "#"} download className="text-[10px] font-black text-slate-700 border border-slate-200 px-2 py-1 rounded bg-white">Patta</a>
                      <a href={rec.chittaDocumentPath || "#"} download className="text-[10px] font-black text-slate-700 border border-slate-200 px-2 py-1 rounded bg-white">Chitta</a>
                      <a href={rec.fmbCopyPath || "#"} download className="text-[10px] font-black text-indigo-700 border border-indigo-100 px-2 py-1 rounded bg-indigo-50">FMB</a>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Village Public Land Records Registry & Policy Enforcement Testing */}
          <section className="bg-white rounded-xl border border-slate-200 shadow-xs p-5">
            <div className="flex justify-between items-center mb-3">
              <div className="flex items-center gap-2">
                <FolderOpen className="w-4 h-4 text-amber-600" />
                <h3 className="text-sm font-black text-slate-800 uppercase tracking-wide">Village Registry Index (Zero Trust Protection)</h3>
              </div>
              <span className="text-[10px] font-extrabold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded">
                Real-Time Telemetry Protected
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mb-3 leading-relaxed">
              Public index of survey parcels in {villageName}. Inspecting deeds registered to another owner triggers the Zero Trust PEP Policy: <b className="text-rose-600 font-bold">-10 pts penalty</b> per unauthorized attempt.
            </p>
            <div className="grid gap-2.5">
              {otherVillageRecords.map((rec) => (
                <div key={rec.id} className="border border-slate-200 rounded-lg p-2.5 bg-slate-50/30 flex justify-between items-center">
                  <div>
                    <div className="text-[10px] font-mono font-bold text-slate-900">Survey #{rec.surveyNumber} • {rec.area}</div>
                    <div className="text-xs text-slate-600 font-medium">Registered Owner: <b className="text-slate-800">{rec.ownerName}</b></div>
                  </div>
                  <button
                    onClick={() => handleInspectDocument(rec.id, rec.ownerName)}
                    disabled={inspectingDocId === rec.id}
                    className="text-[10px] font-bold text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200 px-2.5 py-1.5 rounded transition-all cursor-pointer flex items-center gap-1 shrink-0"
                    title="Attempt inspection to test real-time PEP failure and -10 pts penalty"
                  >
                    <AlertCircle className="w-3 h-3 text-rose-600" />
                    Inspect Deed (Unauthorized)
                  </button>
                </div>
              ))}
            </div>
          </section>

          <section className="bg-white rounded-xl border border-slate-200 shadow-xs p-5">
            <div className="flex items-center gap-2 mb-4">
              <ClipboardCheck className="w-4 h-4 text-indigo-600" />
              <h3 className="text-sm font-black text-slate-800 uppercase tracking-wide">Applications</h3>
            </div>
            <div className="space-y-3">
              {recentApplications.length === 0 ? (
                <div className="text-xs text-slate-500">No recent applications.</div>
              ) : recentApplications.map((app) => (
                <div key={app.id} className="flex justify-between items-center border-b border-slate-100 pb-2 last:border-0">
                  <div>
                    <div className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">{app.id}</div>
                    <div className="text-xs font-black text-slate-800 mt-1">{app.applicationType}</div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] font-black text-indigo-600 uppercase">{app.status}</span>
                    <div className="text-[10px] text-slate-500 mt-1">{new Date(app.submissionDate).toLocaleDateString()}</div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div className="lg:col-span-5">
          <section className="bg-white rounded-xl border border-slate-200 shadow-xs p-5">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-indigo-600" />
              <h3 className="text-sm font-black text-slate-800 uppercase tracking-wide">New Application</h3>
            </div>
            <form className="space-y-3 mt-4" onSubmit={submitApplication}>
              {error && <div className="text-[10px] font-bold text-rose-700 bg-rose-50 border border-rose-100 rounded px-3 py-2">{error}</div>}

              <div className="space-y-1">
                <label className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">Applicant</label>
                <input value={session.userName} disabled className="w-full px-3 py-2 border border-slate-200 rounded-lg bg-slate-50 text-xs" />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">Land Record</label>
                <select value={form.landRecordId} onChange={(e) => {
                  const rec = ownedRecords.find((r) => r.id === e.target.value);
                  setForm({ ...form, landRecordId: e.target.value, surveyNumber: rec?.surveyNumber || "" });
                }} className="w-full px-3 py-2 border border-slate-200 rounded-lg bg-white text-xs" required>
                  {ownedRecords.map((rec) => <option key={rec.id} value={rec.id}>{rec.surveyNumber} - {rec.villageName}</option>)}
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">Survey Number</label>
                <input value={form.surveyNumber} disabled className="w-full px-3 py-2 border border-slate-200 rounded-lg bg-slate-50 text-xs" />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">Application Type</label>
                <select value={form.applicationType} onChange={(e) => setForm({ ...form, applicationType: e.target.value as any })} className="w-full px-3 py-2 border border-slate-200 rounded-lg bg-white text-xs" required>
                  <option value="Patta">Patta-related service</option>
                  <option value="Chitta">Chitta-related service</option>
                  <option value="Land Transfer">Land Transfer</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">Reason</label>
                <textarea value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} rows={3} required className="w-full px-3 py-2 border border-slate-200 rounded-lg bg-white text-xs" placeholder="Reason for request" />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">Supporting Document reference</label>
                <input value={form.supportingDocumentReference} onChange={(e) => setForm({ ...form, supportingDocumentReference: e.target.value })} className="w-full px-3 py-2 border border-slate-200 rounded-lg bg-white text-xs" placeholder="Upload/reference" />
              </div>

              <div className="flex justify-end">
                <button type="submit" disabled={loading} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-[11px] font-black hover:bg-indigo-700">
                  {loading ? "Submitting..." : "Submit Application"}
                </button>
              </div>
            </form>
          </section>
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          {title: "Patta", icon: FileText, color: "bg-emerald-50 text-emerald-700 border-emerald-100"},
          {title: "Chitta", icon: ClipboardCheck, color: "bg-amber-50 text-amber-700 border-amber-100"},
          {title: "FMB Sketch", icon: Landmark, color: "bg-indigo-50 text-indigo-700 border-indigo-100"},
          {title: "Notifications", icon: Bell, color: "bg-slate-50 text-slate-700 border-slate-100"}
        ].map((item, idx) => {
          const Icon = item.icon;
          return <div key={idx} className={`border rounded-xl p-4 ${item.color}`}> <div className="flex items-center gap-2"><Icon className="w-4 h-4"/><span className="text-[10px] font-black uppercase tracking-widest">{item.title}</span></div></div>;
        })}
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <div className="flex items-center gap-2"><User className="w-4 h-4 text-indigo-600"/><span className="font-black text-slate-800 text-xs uppercase">Profile</span></div>
          <div className="text-[11px] text-slate-500 mt-3">{session.userName} • {user?.email || "Citizen"}</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <div className="flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-indigo-600"/><span className="font-black text-slate-800 text-xs uppercase">Security Activity</span></div>
          <div className="text-[11px] text-slate-500 mt-3">Device: {session.deviceFingerprint || "Unknown"} • IP: {session.ipAddress}</div>
        </div>
      </section>

      {/* Certified Land Document Modal */}
      {viewingDoc && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl border border-slate-200">
            <div className="p-6 border-b border-slate-100 flex justify-between items-center bg-indigo-900 text-white rounded-t-2xl">
              <div>
                <span className="text-[10px] font-black uppercase tracking-widest text-emerald-400">Zero Trust Certified Extract</span>
                <h3 className="text-base font-black mt-0.5">{viewingDoc.title}</h3>
                <p className="text-xs text-indigo-200">{viewingDoc.documentType} - Survey #{viewingDoc.surveyNumber}</p>
              </div>
              <button 
                onClick={() => setViewingDoc(null)} 
                className="w-8 h-8 rounded-full bg-white/10 hover:bg-white/20 flex items-center justify-center text-white text-sm font-bold cursor-pointer transition-all"
              >
                ✕
              </button>
            </div>

            <div className="p-6 space-y-4 text-xs">
              <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl flex items-center justify-between text-emerald-900">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-600" />
                  <div>
                    <div className="font-black text-xs">Cryptographically Certified Deed</div>
                    <div className="text-[10px] text-emerald-700">Digital Seal: {viewingDoc.digitalSeal}</div>
                  </div>
                </div>
                <span className="px-2 py-1 rounded bg-emerald-100 text-emerald-800 font-mono text-[10px] font-bold">
                  {viewingDoc.verificationStatus}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-100">
                  <span className="text-[9px] font-bold text-slate-400 uppercase block">Registered Owner</span>
                  <span className="font-bold text-slate-800 text-xs">{viewingDoc.ownerName}</span>
                </div>
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-100">
                  <span className="text-[9px] font-bold text-slate-400 uppercase block">Village / Taluk</span>
                  <span className="font-bold text-slate-800 text-xs">{viewingDoc.village} / {viewingDoc.taluk}</span>
                </div>
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-100">
                  <span className="text-[9px] font-bold text-slate-400 uppercase block">Total Extent / Area</span>
                  <span className="font-bold text-slate-800 text-xs">{viewingDoc.extent}</span>
                </div>
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-100">
                  <span className="text-[9px] font-bold text-slate-400 uppercase block">Land Classification</span>
                  <span className="font-bold text-slate-800 text-xs">{viewingDoc.landType}</span>
                </div>
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-100">
                  <span className="text-[9px] font-bold text-slate-400 uppercase block">Patta Number</span>
                  <span className="font-mono font-bold text-slate-800 text-xs">{viewingDoc.pattaNumber}</span>
                </div>
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-100">
                  <span className="text-[9px] font-bold text-slate-400 uppercase block">Chitta Number</span>
                  <span className="font-mono font-bold text-slate-800 text-xs">{viewingDoc.chittaNumber}</span>
                </div>
              </div>

              <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-[9px] font-bold text-slate-400 uppercase block mb-1">SHA-256 Ledger Hash</span>
                <code className="text-[10px] font-mono text-indigo-700 break-all select-all block bg-white p-2 rounded border border-slate-200">
                  {viewingDoc.documentHash}
                </code>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={() => setViewingDoc(null)}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold transition-all cursor-pointer"
                >
                  Close Certified Document
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
