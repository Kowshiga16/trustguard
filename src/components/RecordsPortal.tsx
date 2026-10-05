/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { 
  Search, Plus, Edit, FileText, Lock, ShieldAlert, CheckCircle, RefreshCw, X,
  Eye, ShieldCheck, AlertTriangle, FileCheck, ExternalLink, Filter, Check, Clock,
  Mail, Key, ArrowRight, AlertCircle
} from "lucide-react";
import { LandRecord, RoleName, ActiveSession, Village } from "../types";

interface RecordsPortalProps {
  records: LandRecord[];
  session: ActiveSession | null;
  villages: Village[];
  onAddRecord: (record: any) => Promise<boolean>;
  onEditRecord: (id: string, record: any) => Promise<boolean>;
  onSubmitMutation: (recordId: string, proposedOwner: string, requestType: string, remarks: string) => Promise<boolean>;
  onSessionUpdate?: (updatedSession: ActiveSession) => void;
}

export default function RecordsPortal({
  records,
  session,
  villages,
  onAddRecord,
  onEditRecord,
  onSubmitMutation,
  onSessionUpdate
}: RecordsPortalProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterDistrict, setFilterDistrict] = useState("all");
  const [filterVillage, setFilterVillage] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterClassification, setFilterClassification] = useState("all");
  const [filterVerification, setFilterVerification] = useState("all");
  const [filterType, setFilterType] = useState("all");

  const [showAddModal, setShowAddModal] = useState(false);
  const [showMutateModal, setShowMutateModal] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState<LandRecord | null>(null);

  // Document Access Control states
  const [showDocViewerModal, setShowDocViewerModal] = useState(false);
  const [viewingDocPayload, setViewingDocPayload] = useState<any>(null);
  const [showDocDenialModal, setShowDocDenialModal] = useState(false);
  const [docDenialReason, setDocDenialReason] = useState("");
  const [docDenialDecision, setDocDenialDecision] = useState("DENIED");
  const [lastAttemptedDocId, setLastAttemptedDocId] = useState<string | null>(null);
  const [otpCode, setOtpCode] = useState("");
  const [verifyingOtp, setVerifyingOtp] = useState(false);
  const [resendingOtp, setResendingOtp] = useState(false);
  const [otpSuccessMsg, setOtpSuccessMsg] = useState("");
  const [otpErrorMsg, setOtpErrorMsg] = useState("");

  // Record Details Modal state
  const [showRecordDetailsModal, setShowRecordDetailsModal] = useState(false);
  const [selectedDetailRecord, setSelectedDetailRecord] = useState<LandRecord | null>(null);

  // Form states for adding/editing record
  const [surveyNum, setSurveyNum] = useState("");
  const [owner, setOwner] = useState("");
  const [ownerPhone, setOwnerPhone] = useState("");
  const [selectedVil, setSelectedVil] = useState("");
  const [area, setArea] = useState("");
  const [landType, setLandType] = useState<any>("Agricultural");

  // Form states for submitting mutation request
  const [proposedOwner, setProposedOwner] = useState("");
  const [mutationType, setMutationType] = useState("Transfer");
  const [remarks, setRemarks] = useState("");

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [showProperties, setShowProperties] = useState(false);

  if (!session) return null;

  const isReadOnly = session.currentTrustScore < 60;
  const isRestricted = session.currentTrustScore >= 60 && session.currentTrustScore < 80;
  const isDEO = session.role === RoleName.DataEntryOperator;
  const isCitizen = session.role === RoleName.Citizen;
  const isAdmin = session.role === RoleName.SystemAdministrator;

  const villageById = new Map(villages.map((v) => [v.id, v]));
  const citizenOwnedRecords = records.filter((rec) => rec.ownerName === session.userName);

  // Unique list of districts
  const distinctDistricts = Array.from(new Set(records.map(r => r.district || "Kancheepuram"))).filter(Boolean);

  // Filter records
  const filteredRecords = records.filter((rec) => {
    const matchesSearch = 
      !searchTerm.trim() ||
      rec.surveyNumber.toLowerCase().includes(searchTerm.toLowerCase().trim()) || 
      rec.ownerName.toLowerCase().includes(searchTerm.toLowerCase().trim()) || 
      rec.villageName.toLowerCase().includes(searchTerm.toLowerCase().trim());
    
    const matchesDistrict = filterDistrict === "all" || (rec.district || "").toLowerCase() === filterDistrict.toLowerCase();
    const matchesVillage = filterVillage === "all" || rec.villageId === filterVillage;
    const matchesStatus = filterStatus === "all" || rec.status === filterStatus;
    const matchesClassification = filterClassification === "all" || rec.documentClassification === filterClassification;
    const matchesVerification = filterVerification === "all" || rec.verificationStatus === filterVerification;
    const matchesType = filterType === "all" || rec.landType === filterType;

    return matchesSearch && matchesDistrict && matchesVillage && matchesStatus && matchesClassification && matchesVerification && matchesType;
  });

  const handleOpenMutate = (rec: LandRecord) => {
    setSelectedRecord(rec);
    setProposedOwner("");
    setRemarks("");
    setShowMutateModal(true);
  };

  const handleMutateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedRecord || !proposedOwner.trim()) return;

    setLoading(true);
    setErrorMsg("");

    try {
      const ok = await onSubmitMutation(selectedRecord.id, proposedOwner, mutationType, remarks);
      if (ok) {
        setShowMutateModal(false);
        setSelectedRecord(null);
      } else {
        setErrorMsg("Failed to submit mutation request. Ensure your Trust Score is >= 80.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "An error occurred.");
    } finally {
      setLoading(false);
    }
  };

  const handleViewDoc = async (id: string) => {
    if (!session) return;
    setLastAttemptedDocId(id);
    setOtpCode("");
    setOtpErrorMsg("");
    setOtpSuccessMsg("");

    try {
      const res = await fetch(`/api/records/${id}/view`, {
        headers: { Authorization: session.id }
      });
      const data = await res.json();
      if (res.ok && data.authorized) {
        setViewingDocPayload(data);
        setShowDocViewerModal(true);
        setShowDocDenialModal(false);
        if (data.evaluation?.trustScore !== undefined) {
          const updatedSession = { ...session, currentTrustScore: data.evaluation.trustScore };
          onSessionUpdate?.(updatedSession);
        }
      } else {
        setDocDenialReason(data.message || data.error || "Access Denied by Security Policy");
        setDocDenialDecision(data.decision || "DENIED");
        setShowDocDenialModal(true);
        if (data.trustScore !== undefined) {
          const updatedSession = { ...session, currentTrustScore: data.trustScore };
          onSessionUpdate?.(updatedSession);
        }
      }
    } catch (err: any) {
      setDocDenialReason(err.message || "Failed to contact authorization server");
      setDocDenialDecision("ERROR");
      setShowDocDenialModal(true);
    }
  };

  const handleModalVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otpCode || otpCode.trim().length !== 6) {
      setOtpErrorMsg("Please enter the 6-digit OTP code received in your email.");
      return;
    }
    if (!session) return;

    setVerifyingOtp(true);
    setOtpErrorMsg("");
    setOtpSuccessMsg("");

    try {
      const res = await fetch("/api/security/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId: session.id,
          otpCode: otpCode.trim()
        })
      });

      const data = await res.json();
      if (res.ok && data.success && data.session) {
        setOtpSuccessMsg(`Identity verified! Trust score restored to ${data.session.currentTrustScore}/100.`);
        onSessionUpdate?.(data.session);

        // Auto-decrypt and open document
        setTimeout(async () => {
          setShowDocDenialModal(false);
          setOtpCode("");
          setOtpSuccessMsg("");
          if (lastAttemptedDocId) {
            await handleViewDoc(lastAttemptedDocId);
          }
        }, 800);
      } else {
        setOtpErrorMsg(data.message || "Invalid or expired OTP code. Please check your email or request a new code.");
      }
    } catch (err: any) {
      setOtpErrorMsg(err?.message || "Failed to contact verification gateway.");
    } finally {
      setVerifyingOtp(false);
    }
  };

  const handleModalResendOtp = async () => {
    if (!session) return;
    setResendingOtp(true);
    setOtpErrorMsg("");
    setOtpSuccessMsg("");
    try {
      const res = await fetch("/api/security/request-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId: session.id,
          reason: "User requested OTP resend from Document Access Restricted portal"
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setOtpSuccessMsg(`A fresh 6-digit verification code has been dispatched to ${session.userEmail || "your email"}!`);
        setTimeout(() => setOtpSuccessMsg(""), 5000);
      } else {
        setOtpErrorMsg(data.message || "Failed to resend OTP. Please try again.");
      }
    } catch (err: any) {
      setOtpErrorMsg(err?.message || "Failed to resend OTP.");
    } finally {
      setResendingOtp(false);
    }
  };

  const handleOpenDetails = (rec: LandRecord) => {
    setSelectedDetailRecord(rec);
    setShowRecordDetailsModal(true);
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!surveyNum || !owner || !selectedVil || !area) return;

    setLoading(true);
    setErrorMsg("");

    try {
      const payload = {
        surveyNumber: surveyNum,
        ownerName: owner,
        ownerPhone,
        villageId: selectedVil,
        area,
        landType
      };
      const ok = await onAddRecord(payload);
      if (ok) {
        setShowAddModal(false);
        setSurveyNum("");
        setOwner("");
        setOwnerPhone("");
        setSelectedVil("");
        setArea("");
      } else {
        setErrorMsg("Failed to add land record. Check authorization and trust score.");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "An error occurred.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-xs border border-slate-200 p-6 flex flex-col h-full">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-base font-bold text-slate-800 tracking-tight">Revenue Land Records Registry</h3>
          <p className="text-xs text-slate-500 mt-0.5">Continuous evaluation determines active viewing boundary.</p>
        </div>

        <div className="flex items-center gap-2">
          {/* Action button based on Role */}
          {isDEO && (
            <button
              onClick={() => {
                if (isReadOnly) return;
                setErrorMsg("");
                setShowAddModal(true);
              }}
              disabled={isReadOnly}
              className={`flex items-center gap-1.5 text-xs font-bold px-4 py-2 rounded-lg shadow-xs transition-all cursor-pointer ${
                isReadOnly
                  ? "bg-slate-100 text-slate-400 border border-slate-200 cursor-not-allowed"
                  : "bg-indigo-600 hover:bg-indigo-700 text-white shadow-sm shadow-indigo-100"
              }`}
            >
              {isReadOnly ? <Lock className="w-3.5 h-3.5" /> : <Plus className="w-3.5 h-3.5" />}
              Add Land Record
            </button>
          )}

          {isCitizen && (
            <button
              onClick={() => setShowProperties(true)}
              className="flex items-center gap-1.5 text-xs font-bold px-4 py-2 rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 transition-all cursor-pointer"
            >
              <FileText className="w-3.5 h-3.5" />
              My Properties
            </button>
          )}
        </div>
      </div>

      {/* Trust Warnings */}
      {isReadOnly && !isAdmin && (
        <div className="mb-5 bg-amber-50/70 border border-amber-200/60 p-4 rounded-lg flex items-start gap-3">
          <ShieldAlert className="w-4.5 h-4.5 text-amber-600 shrink-0 mt-0.5" />
          <p className="text-xs text-amber-800 leading-relaxed font-medium">
            <b>PEP Enforced Read-Only Mode:</b> Your current Trust Score is <b>{session.currentTrustScore}/100</b> (High Risk). Land records are viewable in Read-Only mode. Mutations, additions, and approvals are locked. Complete Step-Up OTP to restore full access.
          </p>
        </div>
      )}

      {isRestricted && !isAdmin && (
        <div className="mb-5 bg-blue-50/70 border border-blue-200/60 p-4 rounded-lg flex items-start gap-3">
          <ShieldAlert className="w-4.5 h-4.5 text-blue-600 shrink-0 mt-0.5" />
          <p className="text-xs text-blue-800 leading-relaxed font-medium">
            <b>Restricted Access Mode:</b> Your current Trust Score is <b>{session.currentTrustScore}/100</b> (Medium Risk). Document viewing is permitted. Step-Up OTP authentication is required for sensitive mutations and approvals.
          </p>
        </div>
      )}

      {isAdmin && (
        <div className="mb-5 bg-indigo-50/60 border border-indigo-100 p-4 rounded-lg flex items-start gap-3">
          <ShieldAlert className="w-4.5 h-4.5 text-indigo-600 shrink-0 mt-0.5" />
          <p className="text-xs text-indigo-800 leading-relaxed font-medium">
            <b>Separation of Duties Active:</b> As System Administrator, you are blocked from viewing or altering database values to prevent insider coercion. Land data payloads are restricted.
          </p>
        </div>
      )}

      {/* Search and Advanced Filters */}
      {!isAdmin && (
        <div className="space-y-3 mb-5 bg-white p-4 rounded-xl border border-slate-250 shadow-xs">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3.5 top-3 w-3.5 h-3.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search by survey number, owner name, or village..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-slate-50/50 border border-slate-250 rounded-lg text-xs focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 text-slate-800 font-medium"
              />
            </div>
            
            {/* Reset button */}
            {(searchTerm || filterDistrict !== "all" || filterVillage !== "all" || filterStatus !== "all" || filterClassification !== "all" || filterVerification !== "all" || filterType !== "all") && (
              <button
                onClick={() => {
                  setSearchTerm("");
                  setFilterDistrict("all");
                  setFilterVillage("all");
                  setFilterStatus("all");
                  setFilterClassification("all");
                  setFilterVerification("all");
                  setFilterType("all");
                }}
                className="px-3 py-2 text-xs font-bold text-slate-600 hover:text-slate-900 border border-slate-250 rounded-lg bg-slate-50 hover:bg-slate-100 transition-colors shrink-0"
              >
                Clear Filters
              </button>
            )}
          </div>

          {/* Filter dropdowns row */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 pt-1 text-xs">
            {/* District Filter */}
            <div>
              <label className="block text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">District</label>
              <select
                value={filterDistrict}
                onChange={(e) => setFilterDistrict(e.target.value)}
                className="w-full border border-slate-250 bg-slate-50/50 rounded-lg py-1.5 px-2.5 text-xs text-slate-700 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500 cursor-pointer"
              >
                <option value="all">All Districts</option>
                {distinctDistricts.map((d) => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
            </div>

            {/* Village Filter */}
            <div>
              <label className="block text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">Village</label>
              <select
                value={filterVillage}
                onChange={(e) => setFilterVillage(e.target.value)}
                className="w-full border border-slate-250 bg-slate-50/50 rounded-lg py-1.5 px-2.5 text-xs text-slate-700 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500 cursor-pointer"
              >
                <option value="all">All Villages</option>
                {villages.map((v) => (
                  <option key={v.id} value={v.id}>{v.name}</option>
                ))}
              </select>
            </div>

            {/* Classification Filter */}
            <div>
              <label className="block text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">Classification</label>
              <select
                value={filterClassification}
                onChange={(e) => setFilterClassification(e.target.value)}
                className="w-full border border-slate-250 bg-slate-50/50 rounded-lg py-1.5 px-2.5 text-xs text-slate-700 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500 cursor-pointer"
              >
                <option value="all">All Security Levels</option>
                <option value="Public">Public</option>
                <option value="Restricted">Restricted</option>
                <option value="Confidential">Confidential</option>
              </select>
            </div>

            {/* Verification Filter */}
            <div>
              <label className="block text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">Verification</label>
              <select
                value={filterVerification}
                onChange={(e) => setFilterVerification(e.target.value)}
                className="w-full border border-slate-250 bg-slate-50/50 rounded-lg py-1.5 px-2.5 text-xs text-slate-700 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500 cursor-pointer"
              >
                <option value="all">All Verifications</option>
                <option value="Verified">Verified</option>
                <option value="Pending Verification">Pending</option>
                <option value="Rejected">Rejected</option>
              </select>
            </div>

            {/* Ownership Status Filter */}
            <div>
              <label className="block text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">Ownership Status</label>
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="w-full border border-slate-250 bg-slate-50/50 rounded-lg py-1.5 px-2.5 text-xs text-slate-700 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500 cursor-pointer"
              >
                <option value="all">All Statuses</option>
                <option value="Active">Active</option>
                <option value="Mutation Pending">Mutation Pending</option>
                <option value="Disputed">Disputed</option>
              </select>
            </div>

            {/* Land Type Filter */}
            <div>
              <label className="block text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">Land Type</label>
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="w-full border border-slate-250 bg-slate-50/50 rounded-lg py-1.5 px-2.5 text-xs text-slate-700 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500 cursor-pointer"
              >
                <option value="all">All Types</option>
                <option value="Agricultural">Agricultural</option>
                <option value="Commercial">Commercial</option>
                <option value="Residential">Residential</option>
                <option value="Forest">Forest</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Records Table */}
      {!isAdmin ? (
        <div className="flex-1 overflow-x-auto min-h-[300px] border border-slate-200 rounded-lg">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-50/75 border-b border-slate-200 text-slate-500 text-[10px] uppercase font-extrabold tracking-widest">
                <th className="py-3 px-4">Survey Number</th>
                <th className="py-3 px-4">Owner Name</th>
                <th className="py-3 px-4">Village / Taluk</th>
                <th className="py-3 px-4">Area</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Verification</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs text-slate-700">
              {filteredRecords.map((rec) => (
                <tr key={rec.id} className="hover:bg-slate-50/40 transition-colors">
                  <td className="py-3.5 px-4 font-mono font-bold text-slate-900">
                    {rec.surveyNumber}
                    {(rec as any).isCrossJurisdiction && (
                      <span className="block mt-0.5 text-[9px] font-black uppercase text-amber-600 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded w-max">
                        Cross-Jurisdiction
                      </span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 font-semibold text-slate-800">{rec.ownerName}</td>
                  <td className="py-3.5 px-4 text-slate-500 font-medium">
                    {rec.villageName}
                    <span className="text-[10px] text-slate-400 block">{rec.taluk || "Tambaram"}</span>
                  </td>
                  <td className="py-3.5 px-4 font-mono font-medium text-slate-600">{rec.area}</td>
                  <td className="py-3.5 px-4">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${
                      rec.documentClassification === "Public" ? "bg-emerald-50 text-emerald-700 border-emerald-200/50" :
                      rec.documentClassification === "Restricted" ? "bg-amber-50 text-amber-700 border-amber-200/50" :
                      "bg-purple-50 text-purple-700 border-purple-200/50"
                    }`}>
                      {rec.documentClassification || "Public"}
                    </span>
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${
                      rec.verificationStatus === "Verified" ? "bg-emerald-50 text-emerald-700 border-emerald-200/50" :
                      rec.verificationStatus === "Rejected" ? "bg-rose-50 text-rose-700 border-rose-200/50" :
                      "bg-amber-50 text-amber-700 border-amber-200/50"
                    }`}>
                      {rec.verificationStatus === "Verified" && <Check className="w-2.5 h-2.5 text-emerald-600" />}
                      {rec.verificationStatus || "Verified"}
                    </span>
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`inline-flex items-center gap-1 font-bold ${
                      rec.status === "Active" ? "text-emerald-600" :
                      rec.status === "Mutation Pending" ? "text-amber-600" : "text-rose-600"
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${
                        rec.status === "Active" ? "bg-emerald-500" :
                        rec.status === "Mutation Pending" ? "bg-amber-500" : "bg-rose-500"
                      }`}></span>
                      {rec.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-right space-x-1.5 shrink-0">
                    {/* View Doc button */}
                    <button
                      onClick={() => handleViewDoc(rec.id)}
                      className="inline-flex items-center gap-1 text-[11px] font-bold px-2.5 py-1.5 rounded-lg transition-all cursor-pointer bg-slate-100 text-slate-700 hover:bg-slate-200 border border-slate-300"
                      title="Inspect Certified Extract (Zero Trust PDP Evaluated)"
                    >
                      <FileText className="w-3 h-3 text-indigo-600" />
                      View Doc
                    </button>

                    {/* Details modal button */}
                    <button
                      onClick={() => handleOpenDetails(rec)}
                      className="inline-flex items-center gap-1 text-[11px] font-bold px-2.5 py-1.5 rounded-lg transition-all cursor-pointer bg-slate-50 text-slate-600 hover:bg-slate-100 border border-slate-250"
                      title="View Full Metadata & Audit Information"
                    >
                      <Eye className="w-3 h-3 text-slate-500" />
                      Details
                    </button>

                    {/* Mutation Submit (Citizen or DEO) */}
                    {(isCitizen || isDEO) && rec.status === "Active" && (
                      <button
                        onClick={() => handleOpenMutate(rec)}
                        className={`inline-flex items-center gap-1 text-[11px] font-bold px-2.5 py-1.5 rounded-lg transition-all cursor-pointer ${
                          isReadOnly
                            ? "bg-slate-100 text-slate-400 border border-slate-200 cursor-not-allowed"
                            : "bg-indigo-600 hover:bg-indigo-700 text-white shadow-xs"
                        }`}
                        disabled={isReadOnly}
                      >
                        {isReadOnly ? <Lock className="w-3 h-3" /> : <Plus className="w-3 h-3" />}
                        Mutate
                      </button>
                    )}
                    {rec.status === "Mutation Pending" && (
                      <span className="text-[10px] font-bold text-slate-500 bg-slate-50 border border-slate-200 py-1 px-2 rounded-lg">
                        Pending
                      </span>
                    )}
                  </td>
                </tr>
              ))}
              {filteredRecords.length === 0 && (
                <tr>
                  <td colSpan={8} className="text-center py-12 text-slate-400 text-xs font-semibold">
                    No land records match the selected filters or search query.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="flex-1 flex flex-col items-center justify-center p-8 text-center border border-dashed border-slate-200 rounded-xl bg-slate-50/50">
          <Lock className="w-10 h-10 text-slate-300 mb-3" />
          <h4 className="text-sm font-bold text-slate-700">Access Restricted for Admins</h4>
          <p className="text-xs text-slate-500 mt-1 max-w-sm leading-relaxed">
            The System Administrator role has no legal operational jurisdiction over land deeds. Access to database rows is blocked to enforce strictly audited Separation of Duties (SoD).
          </p>
        </div>
      )}

      {/* Citizen property panel */}
      {showProperties && isCitizen && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-4xl w-full overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="bg-slate-900 text-white p-4.5 flex justify-between items-center border-b border-slate-950">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-indigo-400" />
                <div>
                  <h4 className="font-bold text-sm tracking-tight">My Property Portfolio</h4>
                  <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Owner: {session.userName}</p>
                </div>
              </div>
              <button onClick={() => setShowProperties(false)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 max-h-[70vh] overflow-y-auto">
              {citizenOwnedRecords.length === 0 ? (
                <div className="text-center py-14 text-slate-400 text-xs font-semibold">
                  No properties found for this citizen.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {citizenOwnedRecords.map((rec) => {
                    const village = villageById.get(rec.villageId);
                    return (
                      <div key={rec.id} className="border border-slate-200 rounded-xl bg-slate-50/40 p-4 space-y-3">
                        <div className="flex items-start justify-between gap-4">
                          <div>
                            <div className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500">Survey No</div>
                            <div className="font-mono font-black text-slate-900 mt-1">{rec.surveyNumber}</div>
                          </div>
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${
                            rec.landType === "Agricultural" ? "bg-emerald-50 text-emerald-700 border-emerald-200/50" :
                            rec.landType === "Commercial" ? "bg-violet-50 text-violet-700 border-violet-200/50" :
                            rec.landType === "Residential" ? "bg-blue-50 text-blue-700 border-blue-200/50" : "bg-amber-50 text-amber-700 border-amber-200/50"
                          }`}>{rec.landType}</span>
                        </div>

                        <div className="grid grid-cols-2 gap-3 text-[11px]">
                          <div className="bg-white rounded-lg border border-slate-200 p-2">
                            <div className="text-[9px] font-bold uppercase text-slate-500">Acres / Area</div>
                            <div className="font-extrabold text-slate-800 mt-1">{rec.area}</div>
                          </div>
                          <div className="bg-white rounded-lg border border-slate-200 p-2">
                            <div className="text-[9px] font-bold uppercase text-slate-500">Village</div>
                            <div className="font-extrabold text-slate-800 mt-1">{rec.villageName}</div>
                          </div>
                          <div className="bg-white rounded-lg border border-slate-200 p-2">
                            <div className="text-[9px] font-bold uppercase text-slate-500">Taluk</div>
                            <div className="font-extrabold text-slate-800 mt-1">{village?.taluk || "N/A"}</div>
                          </div>
                          <div className="bg-white rounded-lg border border-slate-200 p-2">
                            <div className="text-[9px] font-bold uppercase text-slate-500">District</div>
                            <div className="font-extrabold text-slate-800 mt-1">{village?.district || "N/A"}</div>
                          </div>
                        </div>

                        <div className="bg-white rounded-lg border border-slate-200 p-3 text-[11px] space-y-2">
                          <div className="flex items-center justify-between gap-4">
                            <span className="font-bold text-slate-500">Patta</span>
                            {rec.pattaDocumentPath ? (
                              <a
                                href={rec.pattaDocumentPath}
                                download
                                className="font-mono text-slate-800 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded px-2 py-1 text-[10px] font-bold cursor-pointer"
                                title={rec.pattaNumber || "Patta document"}
                              >
                                {rec.pattaNumber || "Download Patta"}
                              </a>
                            ) : (
                              <span className="font-mono text-slate-500">Not attached</span>
                            )}
                          </div>

                          <div className="flex items-center justify-between gap-4">
                            <span className="font-bold text-slate-500">Chitta</span>
                            {rec.chittaDocumentPath ? (
                              <a
                                href={rec.chittaDocumentPath}
                                download
                                className="font-mono text-slate-800 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded px-2 py-1 text-[10px] font-bold cursor-pointer"
                                title={rec.chittaNumber || "Chitta document"}
                              >
                                {rec.chittaNumber || "Download Chitta"}
                              </a>
                            ) : (
                              <span className="font-mono text-slate-500">Not attached</span>
                            )}
                          </div>

                          <div className="flex items-center justify-between gap-4">
                            <span className="font-bold text-slate-500">FMB Copy</span>
                            {rec.fmbCopyPath ? (
                              <a
                                href={rec.fmbCopyPath}
                                download
                                className="font-mono text-indigo-700 underline bg-indigo-50 hover:bg-indigo-100 border border-indigo-100 rounded px-2 py-1 text-[10px] font-bold cursor-pointer"
                                title={rec.fmbCopyPath || "FMB copy not attached"}
                              >
                                Download FMB
                              </a>
                            ) : (
                              <span className="font-mono text-slate-500">Not attached</span>
                            )}
                          </div>
                        </div>

                        <div className="flex justify-between items-center text-[10px] font-bold">
                          <span className="text-slate-500">Status: <span className="text-emerald-600">{rec.status}</span></span>
                          <span className="text-slate-500">Owner: {rec.ownerName}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Submit Mutation Modal */}
      {showMutateModal && selectedRecord && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-md w-full overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="bg-slate-900 text-white p-4.5 flex justify-between items-center border-b border-slate-950">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-indigo-400" />
                <h4 className="font-bold text-sm tracking-tight">Apply Mutation: Survey {selectedRecord.surveyNumber}</h4>
              </div>
              <button onClick={() => setShowMutateModal(false)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleMutateSubmit} className="p-5 space-y-4">
              {errorMsg && <div className="text-xs text-rose-600 bg-rose-50 p-2.5 rounded border border-rose-100">{errorMsg}</div>}

              <div className="text-xs text-slate-500 space-y-1 bg-slate-50 p-3 rounded-lg border border-slate-200">
                <div className="flex justify-between"><span>Current Owner:</span> <span className="font-bold text-slate-700">{selectedRecord.ownerName}</span></div>
                <div className="flex justify-between"><span>Village / Area:</span> <span className="font-mono">{selectedRecord.villageName} / {selectedRecord.area}</span></div>
              </div>

              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Proposed Owner Name</label>
                <input
                  type="text"
                  required
                  value={proposedOwner}
                  onChange={(e) => setProposedOwner(e.target.value)}
                  placeholder="Enter recipient of title deed"
                  className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Mutation Type</label>
                <select
                  value={mutationType}
                  onChange={(e) => setMutationType(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 cursor-pointer"
                >
                  <option value="Transfer">Deed Transfer / Ownership Shift</option>
                  <option value="Division">Partition / Land Division</option>
                  <option value="Correction">Clerical Data Correction</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Remarks / Support Evidence</label>
                <textarea
                  required
                  rows={3}
                  value={remarks}
                  onChange={(e) => setRemarks(e.target.value)}
                  placeholder="Explain transfer grounds (e.g., Legal heir gift deed, sale deed registration)"
                  className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2 text-xs font-semibold">
                <button
                  type="button"
                  onClick={() => setShowMutateModal(false)}
                  className="px-4 py-2 border border-slate-300 rounded-lg text-slate-600 hover:bg-slate-50 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg shadow-sm font-bold flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : "Submit Application"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Record Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-md w-full overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="bg-slate-900 text-white p-4.5 flex justify-between items-center border-b border-slate-950">
              <div className="flex items-center gap-2">
                <Plus className="w-5 h-5 text-indigo-400" />
                <h4 className="font-bold text-sm tracking-tight">Create New Land Deed Record</h4>
              </div>
              <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="p-5 space-y-3.5">
              {errorMsg && <div className="text-xs text-rose-600 bg-rose-50 p-2.5 rounded border border-rose-100">{errorMsg}</div>}

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Survey Number</label>
                  <input
                    type="text"
                    required
                    value={surveyNum}
                    onChange={(e) => setSurveyNum(e.target.value)}
                    placeholder="Ex: 50/4C"
                    className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Land Area (Acres)</label>
                  <input
                    type="text"
                    required
                    value={area}
                    onChange={(e) => setArea(e.target.value)}
                    placeholder="Ex: 2.5 Acres"
                    className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Owner Full Name</label>
                <input
                  type="text"
                  required
                  value={owner}
                  onChange={(e) => setOwner(e.target.value)}
                  placeholder="Full name of title deed holder"
                  className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Owner Contact Number</label>
                <input
                  type="text"
                  required
                  value={ownerPhone}
                  onChange={(e) => setOwnerPhone(e.target.value)}
                  placeholder="Ex: +91 98401 12345"
                  className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Village / Taluk</label>
                  <select
                    required
                    value={selectedVil}
                    onChange={(e) => setSelectedVil(e.target.value)}
                    className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 cursor-pointer"
                  >
                    <option value="">Select Village</option>
                    {villages.map((v) => (
                      <option key={v.id} value={v.id}>{v.name} ({v.taluk})</option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Land Classification</label>
                  <select
                    value={landType}
                    onChange={(e) => setLandType(e.target.value)}
                    className="w-full px-3 py-2 border border-slate-250 bg-slate-50/50 rounded-lg text-xs focus:ring-1 focus:ring-indigo-500 cursor-pointer"
                  >
                    <option value="Agricultural">Agricultural</option>
                    <option value="Commercial">Commercial</option>
                    <option value="Residential">Residential</option>
                    <option value="Forest">Forest</option>
                  </select>
                </div>
              </div>

              <div className="pt-2 flex justify-end gap-2 text-xs font-semibold">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 border border-slate-300 rounded-lg text-slate-600 hover:bg-slate-50 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg shadow-sm font-bold flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : "Save Database Record"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Certified Document Viewer Modal */}
      {showDocViewerModal && viewingDocPayload && viewingDocPayload.documentPayload && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-2xl w-full max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="bg-indigo-950 text-white p-5 flex items-start justify-between border-b border-indigo-900">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-extrabold uppercase tracking-widest bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded">
                    Zero Trust Certified
                  </span>
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                    ROR Title Extract
                  </span>
                </div>
                <h3 className="text-base font-bold text-white tracking-tight">
                  {viewingDocPayload.documentPayload.title}
                </h3>
                <p className="text-xs text-indigo-200 font-medium">
                  {viewingDocPayload.documentPayload.documentType} • Survey #{viewingDocPayload.documentPayload.surveyNumber}
                </p>
              </div>
              <button
                onClick={() => setShowDocViewerModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-white/10 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-700">
              {/* Digital Certificate Seal Banner */}
              <div className="bg-emerald-50/80 border border-emerald-200/80 rounded-xl p-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-emerald-600 text-white flex items-center justify-center shrink-0 shadow-sm">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="text-[11px] font-extrabold text-emerald-900 uppercase tracking-wider">
                      Digital Authentication Seal Valid
                    </div>
                    <div className="text-[10px] font-mono text-emerald-700 font-bold mt-0.5">
                      {viewingDocPayload.documentPayload.digitalSeal}
                    </div>
                  </div>
                </div>
                <span className="text-[9px] font-mono font-bold text-emerald-800 bg-white border border-emerald-300 px-2 py-1 rounded">
                  Issued: {viewingDocPayload.documentPayload.issuedDate}
                </span>
              </div>

              {/* Title Deed Attributes Grid */}
              <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/50 space-y-3">
                <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 pb-2">
                  Registered Land Parcel Characteristics
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  <div>
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Survey Number</span>
                    <span className="font-mono font-bold text-slate-900 text-sm">{viewingDocPayload.documentPayload.surveyNumber}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Title Deed Holder</span>
                    <span className="font-bold text-slate-800">{viewingDocPayload.documentPayload.ownerName}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Land Extent</span>
                    <span className="font-mono font-bold text-slate-800">{viewingDocPayload.documentPayload.extent}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Classification</span>
                    <span className="font-bold text-indigo-700">{viewingDocPayload.documentPayload.landType}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Village</span>
                    <span className="font-medium text-slate-700">{viewingDocPayload.documentPayload.village}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Taluk & District</span>
                    <span className="font-medium text-slate-700">{viewingDocPayload.documentPayload.taluk}, {viewingDocPayload.documentPayload.district}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Patta Number</span>
                    <span className="font-mono text-slate-700">{viewingDocPayload.documentPayload.pattaNumber}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Chitta Number</span>
                    <span className="font-mono text-slate-700">{viewingDocPayload.documentPayload.chittaNumber}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Security Classification</span>
                    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border mt-0.5 ${
                      viewingDocPayload.documentPayload.classification === "Public" ? "bg-emerald-50 text-emerald-700 border-emerald-200" :
                      viewingDocPayload.documentPayload.classification === "Restricted" ? "bg-amber-50 text-amber-700 border-amber-200" :
                      "bg-purple-50 text-purple-700 border-purple-200"
                    }`}>
                      {viewingDocPayload.documentPayload.classification}
                    </span>
                  </div>
                </div>
              </div>

              {/* Cryptographic SHA-256 Hash */}
              <div className="bg-slate-900 text-slate-100 rounded-xl p-3.5 space-y-1 font-mono">
                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span>CRYPTOGRAPHIC SHA-256 DOCUMENT INTEGRITY HASH</span>
                  <span className="text-emerald-400">MATCH VERIFIED</span>
                </div>
                <div className="text-[10px] text-indigo-300 break-all select-all">
                  {viewingDocPayload.documentPayload.documentHash}
                </div>
              </div>

              {/* Associated Documents */}
              {viewingDocPayload.documentPayload.associatedDocuments && viewingDocPayload.documentPayload.associatedDocuments.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                    Associated Land Office Schedules
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    {viewingDocPayload.documentPayload.associatedDocuments.map((doc: any, i: number) => (
                      <div key={i} className="p-3 border border-slate-200 rounded-lg bg-white flex items-center justify-between hover:border-slate-300 transition-colors">
                        <div className="flex items-center gap-2">
                          <FileText className="w-3.5 h-3.5 text-indigo-600" />
                          <span className="text-xs font-semibold text-slate-800">{doc.name}</span>
                        </div>
                        <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-slate-100 text-slate-600">
                          {doc.type}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Zero Trust PDP Real-Time Context Banner */}
              {viewingDocPayload.evaluation && (
                <div className="bg-indigo-50/60 border border-indigo-100 rounded-xl p-3.5 flex items-center justify-between text-[11px]">
                  <div>
                    <span className="text-[10px] font-bold text-indigo-900 uppercase tracking-wider block">
                      PDP Dynamic Evaluation Result
                    </span>
                    <span className="text-indigo-700 font-medium mt-0.5 block">
                      Decision: <b className="font-bold text-emerald-700">{viewingDocPayload.decision}</b> • Trust Score: <b className="font-bold">{viewingDocPayload.evaluation.trustScore}/100</b> ({viewingDocPayload.evaluation.riskLevel} Risk)
                    </span>
                  </div>
                  <div className="text-right">
                    <span className="text-[9px] font-bold uppercase text-slate-500 block">ML Anomaly (NAS)</span>
                    <span className="font-mono font-bold text-indigo-800">
                      {typeof viewingDocPayload.evaluation.normalizedAnomalyScore === "number" ? viewingDocPayload.evaluation.normalizedAnomalyScore.toFixed(4) : "0.0000"}
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-200 bg-slate-50/50 flex items-center justify-between">
              <span className="text-[10px] text-slate-400 font-medium">
                Tamil Nadu Land Information System (e-District Secure Gateway)
              </span>
              <button
                onClick={() => setShowDocViewerModal(false)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs rounded-lg shadow-xs transition-colors cursor-pointer"
              >
                Close Document
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Document Denial / Restriction Modal with Integrated OTP Verification */}
      {showDocDenialModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-white rounded-2xl shadow-2xl border border-rose-200 max-w-md w-full p-6 text-center animate-in fade-in zoom-in-95 duration-150">
            <div className="w-14 h-14 bg-rose-100 text-rose-600 rounded-full flex items-center justify-center mx-auto mb-4 border border-rose-200">
              <ShieldAlert className="w-7 h-7" />
            </div>
            <div className="inline-block px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-rose-50 text-rose-700 border border-rose-200 mb-2">
              Access Decision: {docDenialDecision}
            </div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight mb-2">
              Document Access Restricted
            </h3>
            <p className="text-xs text-slate-600 font-medium leading-relaxed mb-4 bg-slate-50 p-3.5 rounded-xl border border-slate-200 text-left">
              {docDenialReason}
            </p>

            {/* If Decision requires OTP or session is challenged/blocked */}
            {(docDenialDecision === "OTP_REQUIRED" ||
              docDenialDecision === "BLOCKED" ||
              docDenialReason.toLowerCase().includes("otp") ||
              docDenialReason.toLowerCase().includes("step-up")) ? (
              <form onSubmit={handleModalVerifyOtp} className="space-y-4 text-left">
                {/* Email dispatch alert */}
                <div className="bg-indigo-50/80 border border-indigo-100 p-3 rounded-xl flex items-start gap-2.5 text-xs text-indigo-950">
                  <Mail className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-bold text-indigo-950 block text-[11px]">Step-Up Verification Code Dispatched:</span>
                    <p className="text-slate-600 leading-normal text-[11px]">
                      A 6-digit OTP code has been sent to your registered mailbox:
                      <b className="font-mono text-indigo-900 block mt-0.5 break-all">{session?.userEmail || session?.userName || "official account"}</b>
                    </p>
                    <p className="text-[10px] text-slate-500 italic mt-0.5">
                      Check your inbox or Spam folder for the security verification code.
                    </p>
                  </div>
                </div>

                {otpSuccessMsg && (
                  <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 font-bold flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span>{otpSuccessMsg}</span>
                  </div>
                )}

                {otpErrorMsg && (
                  <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 font-bold flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
                    <span>{otpErrorMsg}</span>
                  </div>
                )}

                {/* OTP Input Field */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-[10px] font-bold text-slate-600 uppercase tracking-widest">
                      Enter 6-Digit Email Code
                    </label>
                    <button
                      type="button"
                      onClick={handleModalResendOtp}
                      disabled={resendingOtp || verifyingOtp}
                      className="text-[10px] font-bold text-indigo-600 hover:text-indigo-700 flex items-center gap-1 cursor-pointer disabled:text-slate-400"
                    >
                      <RefreshCw className={`w-3 h-3 ${resendingOtp ? "animate-spin" : ""}`} />
                      {resendingOtp ? "Sending..." : "Resend OTP"}
                    </button>
                  </div>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                      <Key className="h-4 w-4 text-slate-400" />
                    </div>
                    <input
                      type="text"
                      value={otpCode}
                      onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      maxLength={6}
                      placeholder="------"
                      autoFocus
                      className="block w-full pl-10 pr-3 py-2.5 bg-slate-50 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-center tracking-[0.35em] text-xl font-bold placeholder:tracking-normal placeholder:font-sans placeholder:text-xs placeholder:font-semibold"
                    />
                  </div>
                </div>

                <div className="flex items-center gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => {
                      setShowDocDenialModal(false);
                      setOtpCode("");
                      setOtpErrorMsg("");
                      setOtpSuccessMsg("");
                    }}
                    className="flex-1 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold text-xs rounded-lg transition-colors cursor-pointer text-center"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={verifyingOtp || otpCode.trim().length !== 6}
                    className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-300 disabled:cursor-not-allowed text-white font-bold text-xs rounded-lg shadow-sm transition-all flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    {verifyingOtp ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Verifying...</span>
                      </>
                    ) : (
                      <>
                        <span>Verify & Restore Trust</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </>
                    )}
                  </button>
                </div>
              </form>
            ) : (
              <div>
                <div className="text-[11px] text-slate-500 font-medium mb-5 text-left bg-amber-50/60 border border-amber-200/60 p-3 rounded-lg">
                  <b>Security Guidance:</b> Land deeds are protected by dynamic Zero Trust policies and role-based jurisdiction boundaries.
                </div>
                <button
                  onClick={() => setShowDocDenialModal(false)}
                  className="w-full py-2.5 bg-slate-800 hover:bg-slate-900 text-white font-bold text-xs rounded-lg shadow-xs transition-colors cursor-pointer"
                >
                  Acknowledge & Dismiss
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Record Complete Details Modal */}
      {showRecordDetailsModal && selectedDetailRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-xl w-full p-6 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 mb-4">
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">Comprehensive Record Metadata</span>
                <h3 className="text-base font-bold text-slate-900">Survey #{selectedDetailRecord.surveyNumber}</h3>
              </div>
              <button
                onClick={() => setShowRecordDetailsModal(false)}
                className="text-slate-400 hover:text-slate-600 p-1 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4 text-xs text-slate-700">
              <div className="grid grid-cols-2 gap-3 bg-slate-50/60 p-4 rounded-xl border border-slate-200">
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Owner Name</span>
                  <span className="font-bold text-slate-800">{selectedDetailRecord.ownerName}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Contact Number</span>
                  <span className="font-mono text-slate-700">{selectedDetailRecord.ownerPhone}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Village / Taluk</span>
                  <span className="text-slate-800">{selectedDetailRecord.villageName} ({selectedDetailRecord.taluk || "Tambaram"})</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">District</span>
                  <span className="text-slate-800">{selectedDetailRecord.district || "Kancheepuram"}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Parcel Extent</span>
                  <span className="font-mono font-bold text-slate-800">{selectedDetailRecord.area}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Land Category</span>
                  <span className="font-bold text-indigo-700">{selectedDetailRecord.landType}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Security Classification</span>
                  <span className="font-bold text-purple-700">{selectedDetailRecord.documentClassification || "Public"}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Verification Status</span>
                  <span className="font-bold text-emerald-700">{selectedDetailRecord.verificationStatus || "Verified"}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Patta Number</span>
                  <span className="font-mono text-slate-700">{selectedDetailRecord.pattaNumber || "N/A"}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase block">Chitta Number</span>
                  <span className="font-mono text-slate-700">{selectedDetailRecord.chittaNumber || "N/A"}</span>
                </div>
              </div>

              <div className="bg-slate-900 text-slate-200 p-3 rounded-xl font-mono text-[10px] space-y-1">
                <div className="text-slate-400 font-bold uppercase">Certified Hash (SHA-256)</div>
                <div className="break-all text-indigo-300">{selectedDetailRecord.documentHash || "N/A"}</div>
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                <span>Last Modified By: <b className="text-slate-700">{selectedDetailRecord.lastModifiedBy}</b></span>
                <span>Date: <b className="text-slate-700">{new Date(selectedDetailRecord.lastModifiedAt).toLocaleDateString()}</b></span>
              </div>
            </div>

            <div className="pt-4 mt-4 border-t border-slate-200 flex justify-end gap-2">
              <button
                onClick={() => {
                  setShowRecordDetailsModal(false);
                  handleViewDoc(selectedDetailRecord.id);
                }}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs rounded-lg shadow-xs transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5" />
                Inspect Document Extract
              </button>
              <button
                onClick={() => setShowRecordDetailsModal(false)}
                className="px-4 py-2 border border-slate-300 rounded-lg text-slate-700 hover:bg-slate-50 font-bold text-xs cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
