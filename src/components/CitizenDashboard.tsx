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
}

export default function CitizenDashboard({ session, users, villages, records, applications, onSubmitApplication }: CitizenDashboardProps) {
  const user = users.find((u) => u.id === session.userId) || users.find((u) => u.name === session.userName) || null;
  const ownedRecords = useMemo(() => records.filter((r) => r.ownerName === session.userName), [records, session.userName]);
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

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 space-y-6">
          <section className="bg-white rounded-xl border border-slate-200 shadow-xs p-5">
            <div className="flex justify-between items-center mb-4">
              <div className="flex items-center gap-2">
                <Landmark className="w-4 h-4 text-indigo-600" />
                <h3 className="text-sm font-black text-slate-800 uppercase tracking-wide">My Land Records</h3>
              </div>
              <span className="text-[10px] font-bold text-slate-500">{ownedRecords.length} records</span>
            </div>
            <div className="grid gap-3">
              {ownedRecords.slice(0, 4).map((rec) => (
                <div key={rec.id} className="border border-slate-200 rounded-lg p-3 bg-slate-50/40">
                  <div className="flex justify-between items-center gap-3">
                    <div>
                      <div className="text-[10px] font-extrabold uppercase text-slate-500">Survey #{rec.surveyNumber}</div>
                      <div className="text-xs font-black text-slate-800 mt-1">{rec.villageName} / {rec.area}</div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <a href={rec.pattaDocumentPath || "#"} download className="text-[10px] font-black text-slate-700 border border-slate-200 px-2 py-1 rounded bg-white">Patta</a>
                      <a href={rec.chittaDocumentPath || "#"} download className="text-[10px] font-black text-slate-700 border border-slate-200 px-2 py-1 rounded bg-white">Chitta</a>
                      <a href={rec.fmbCopyPath || "#"} download className="text-[10px] font-black text-indigo-700 border border-indigo-100 px-2 py-1 rounded bg-indigo-50">FMB</a>
                    </div>
                  </div>
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
    </div>
  );
}
