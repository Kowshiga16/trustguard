/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import { 
  ShieldCheck, 
  ShieldAlert, 
  Lock, 
  RefreshCw, 
  UserCheck, 
  HelpCircle, 
  FileText, 
  Terminal, 
  Database,
  ArrowRight,
  Sparkles,
  ChevronRight,
  ShieldAlert as LockIcon
} from "lucide-react";

import { 
  RoleName, 
  ActiveSession, 
  User, 
  LandRecord, 
  MutationRequest, 
  SystemStats, 
  Village,
  Application
} from "./types";

import Navigation from "./components/Navigation";
import TrustProgress from "./components/TrustProgress";
import ThreatSimulator from "./components/ThreatSimulator";
import RecordsPortal from "./components/RecordsPortal";
import MutationsPortal from "./components/MutationsPortal";
import SecurityConsole from "./components/SecurityConsole";
import StatsDashboard from "./components/StatsDashboard";
import OtpVerificationModal from "./components/OtpVerificationModal";
import CitizenDashboard from "./components/CitizenDashboard";
import AdminDashboard from "./components/AdminDashboard";

export default function App() {
  const [users, setUsers] = useState<User[]>([]);
  const [villages, setVillages] = useState<Village[]>([]);
  const [session, setSession] = useState<ActiveSession | null>(null);
  const [records, setRecords] = useState<LandRecord[]>([]);
  const [applications, setApplications] = useState<Application[]>([]);
  const [mutations, setMutations] = useState<MutationRequest[]>([]);
  const [trustLogs, setTrustLogs] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [stats, setStats] = useState<SystemStats>({
    totalRecords: 0,
    activeSessionsCount: 0,
    pendingMutations: 0,
    securityIncidentsCount: 0
  });

  const [activeTab, setActiveTab] = useState<string>("records");
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string>("");
  const [showSignup, setShowSignup] = useState(false);
  const [loginForm, setLoginForm] = useState({
    email: "",
    password: "",
    customDevice: "",
    customIp: ""
  });
  const [signupForm, setSignupForm] = useState({
    name: "",
    email: "",
    password: "",
    roleName: RoleName.Citizen,
    phone: "",
    district: "",
    taluk: "",
    villageId: "",
    registeredDevice: ""
  });

  // Helper for safe JSON fetching
  async function safeFetchJson<T = any>(url: string, options?: RequestInit): Promise<{ ok: boolean; status: number; data?: T; message?: string }> {
    try {
      const res = await fetch(url, options);
      const contentType = res.headers.get("content-type") || "";
      let data: any = undefined;
      let message = "";
      if (contentType.includes("application/json")) {
        data = await res.json();
        if (data && typeof data === "object" && data.message) {
          message = data.message;
        }
      }
      return { ok: res.ok, status: res.status, data, message };
    } catch (err: any) {
      return { ok: false, status: 0, message: err?.message || "Network error" };
    }
  }

  // 1. Initial configuration load
  useEffect(() => {
    async function initSystem() {
      try {
        const usersResult = await safeFetchJson<User[]>("/api/users");
        if (usersResult.ok && Array.isArray(usersResult.data)) {
          setUsers(usersResult.data);
        }

        const vilResult = await safeFetchJson<Village[]>("/api/villages");
        if (vilResult.ok && Array.isArray(vilResult.data)) {
          setVillages(vilResult.data);
        }

        // Check if there's a stored session
        const storedToken = localStorage.getItem("dzt_session_token");
        if (storedToken) {
          const sessResult = await safeFetchJson<ActiveSession>("/api/auth/current-session", {
            headers: { "Authorization": storedToken }
          });
          if (sessResult.ok && sessResult.data) {
            setSession(sessResult.data);
            await loadSessionData(storedToken);
          } else {
            localStorage.removeItem("dzt_session_token");
            setSession(null);
          }
        }
      } catch (err) {
        console.warn("System init error:", err);
      } finally {
        setLoading(false);
      }
    }
    initSystem();
  }, []);

  // 2. Load all records, logs and stats linked to a session
  async function loadSessionData(token: string) {
    try {
      const headers = { "Authorization": token };

      // Land Records (might return 403, we must handle gracefully)
      const recRes = await safeFetchJson<LandRecord[]>("/api/records", { headers });
      if (recRes.ok && Array.isArray(recRes.data)) {
        setRecords(recRes.data);
      } else if (recRes.status === 403 && recRes.data) {
        if ((recRes.data as any).error === "blocked") {
          setSession(prev => prev ? { ...prev, status: "Blocked", currentTrustScore: (recRes.data as any).trustScore ?? 0 } : null);
        }
      } else if (recRes.status === 401) {
        localStorage.removeItem("dzt_session_token");
        setSession(null);
        return;
      }

      // Applications
      const appRes = await safeFetchJson<Application[]>("/api/applications", { headers });
      if (appRes.ok && Array.isArray(appRes.data)) {
        setApplications(appRes.data);
      }

      // Mutations
      const mutRes = await safeFetchJson<MutationRequest[]>("/api/mutations", { headers });
      if (mutRes.ok && Array.isArray(mutRes.data)) {
        setMutations(mutRes.data);
      }

      // Trust Logs
      const tLogsRes = await safeFetchJson<any[]>("/api/security/trust-logs");
      if (tLogsRes.ok && Array.isArray(tLogsRes.data)) {
        setTrustLogs(tLogsRes.data);
      }

      // Audit Logs
      const aLogsRes = await safeFetchJson<any[]>("/api/security/audit-logs");
      if (aLogsRes.ok && Array.isArray(aLogsRes.data)) {
        setAuditLogs(aLogsRes.data);
      }

      // Stats
      const statsRes = await safeFetchJson<SystemStats>("/api/system/stats");
      if (statsRes.ok && statsRes.data) {
        setStats(statsRes.data);
      }
    } catch (err) {
      console.warn("Load session details error:", err);
    }
  }

  // Action: Sign in using a strict email/password request instead of the old demo grid.
  async function handleLogin(email: string, password: string, customDevice?: string, customIp?: string) {
    setLoading(true);
    setErrorMsg("");
    try {
      const res = await safeFetchJson<{ session: ActiveSession; user: User }>("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, customDevice, customIp })
      });
      if (res.ok && res.data?.session) {
        setSession(res.data.session);
        localStorage.setItem("dzt_session_token", res.data.session.id);
        await loadSessionData(res.data.session.id);
        setActiveTab(res.data.session.role === RoleName.SystemAdministrator ? "admin" : "records");
      } else {
        setErrorMsg(res.message || "Login failed");
      }
    } catch (err: any) {
      setErrorMsg(err?.message || "Unable to connect to full-stack authentication gateway.");
    } finally {
      setLoading(false);
    }
  }

  async function handleSignup(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setErrorMsg("");
    try {
      const payload = {
        name: signupForm.name,
        email: signupForm.email,
        password: signupForm.password,
        roleName: signupForm.roleName,
        phone: signupForm.phone,
        assignedJurisdiction: {
          district: signupForm.district,
          taluk: signupForm.taluk,
          villageId: signupForm.villageId || undefined
        },
        registeredDevice: signupForm.registeredDevice || "New_Device"
      };

      const result = await safeFetchJson<{ success: boolean; user: User }>('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (result.ok && result.data?.user) {
        setShowSignup(false);
        setSignupForm({
          name: "",
          email: "",
          password: "",
          roleName: RoleName.Citizen,
          phone: "",
          district: "",
          taluk: "",
          villageId: "",
          registeredDevice: ""
        });
        setErrorMsg("");
        const created = result.data.user;
        setUsers(prev => [...prev, created]);
      } else {
        setErrorMsg(result.message || 'Sign-up failed');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Unable to create the district user.');
    } finally {
      setLoading(false);
    }
  }

  // Action: Logout
  async function handleLogout() {
    if (session) {
      try {
        await safeFetchJson("/api/auth/logout", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sessionId: session.id })
        });
      } catch (err) {
        console.warn("Logout error:", err);
      }
    }
    localStorage.removeItem("dzt_session_token");
    setSession(null);
    setRecords([]);
    setMutations([]);
  }

  // Action: Toggle simulator context switches
  async function handleToggleParam(param: string, value: boolean) {
    if (!session) return;
    try {
      const res = await safeFetchJson<ActiveSession>("/api/simulation/toggle", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify({ sessionId: session.id, param, value })
      });
      if (res.ok && res.data) {
        setSession(res.data);
        await loadSessionData(session.id);
      }
    } catch (err) {
      console.warn("Toggle parameter error:", err);
    }
  }

  // Action: Clear all threat conditions
  async function handleClearPenalties() {
    if (!session) return;
    try {
      const res = await safeFetchJson<ActiveSession>("/api/simulation/toggle", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify({ sessionId: session.id, param: "clearPenalties", value: true })
      });
      if (res.ok && res.data) {
        setSession(res.data);
        await loadSessionData(session.id);
      }
    } catch (err) {
      console.warn("Clear penalties error:", err);
    }
  }

  // Action: Trigger Request Spamming
  async function handleTriggerSpam() {
    if (!session) return;
    try {
      const res = await safeFetchJson<ActiveSession>("/api/simulation/spam-actions", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify({ sessionId: session.id })
      });
      if (res.ok && res.data) {
        setSession(res.data);
        await loadSessionData(session.id);
      }
    } catch (err) {
      console.warn("Trigger spam error:", err);
    }
  }

  // Action: OTP Step Up Verification
  async function handleRequestOtp(): Promise<void> {
    if (!session) return;
    try {
      await safeFetchJson("/api/security/request-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: session.id })
      });
    } catch (err) {
      console.warn("Request OTP error:", err);
    }
  }

  // Action: Trigger simulated role-based low trust OTP challenge
  async function handleTriggerRoleOtpSimulation(): Promise<void> {
    if (!session) return;
    try {
      const res = await safeFetchJson<any>("/api/simulation/trigger-otp-challenge", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify({ sessionId: session.id })
      });
      if (res.ok && res.data?.session) {
        setSession(res.data.session);
        await loadSessionData(session.id);
      }
    } catch (err) {
      console.warn("Trigger role OTP simulation error:", err);
    }
  }

  async function handleVerifyOtp(otpCode: string): Promise<boolean> {
    if (!session) return false;
    try {
      const res = await safeFetchJson<{ success: boolean; session: ActiveSession }>("/api/security/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: session.id, otpCode })
      });
      if (res.ok && res.data?.session) {
        setSession(res.data.session);
        await loadSessionData(session.id);
        return true;
      }
      return false;
    } catch (err) {
      console.warn("Verify OTP error:", err);
      return false;
    }
  }

  // Action: Add new record (DEO only)
  async function handleAddRecord(payload: any): Promise<boolean> {
    if (!session) return false;
    try {
      const res = await safeFetchJson<LandRecord>("/api/records", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        await loadSessionData(session.id);
        return true;
      }
      return false;
    } catch (err: any) {
      console.warn("Add record error:", err);
      return false;
    }
  }

  // Action: Edit record
  async function handleEditRecord(id: string, payload: any): Promise<boolean> {
    if (!session) return false;
    try {
      const res = await safeFetchJson<LandRecord>(`/api/records/${id}`, {
        method: "PUT",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        await loadSessionData(session.id);
        return true;
      }
      return false;
    } catch (err) {
      console.warn("Edit record error:", err);
      return false;
    }
  }

  // Action: Submit a citizen application
  async function handleSubmitApplication(payload: any): Promise<boolean> {
    if (!session) return false;
    try {
      const res = await safeFetchJson<Application>("/api/applications", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        await loadSessionData(session.id);
        return true;
      }
      setErrorMsg(res.message || "Application submission failed");
      return false;
    } catch (err) {
      console.warn("Submit application error:", err);
      return false;
    }
  }

  // Action: Submit Mutation Request
  async function handleSubmitMutation(recordId: string, proposedOwner: string, requestType: string, remarks: string): Promise<boolean> {
    if (!session) return false;
    try {
      const res = await safeFetchJson<MutationRequest>(`/api/records/${recordId}/mutate-request`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify({ proposedOwner, requestType, remarks })
      });
      if (res.ok) {
        await loadSessionData(session.id);
        return true;
      }
      return false;
    } catch (err) {
      console.warn("Submit mutation error:", err);
      return false;
    }
  }

  // Action: Create a revenue-roles user from the System Admin dashboard
  async function handleCreateAdminUser(payload: any): Promise<{ success: boolean; message?: string }> {
    if (!session) return { success: false, message: "No active administrator session found. Please re-login." };
    try {
      const res = await safeFetchJson<any>("/api/admin/users", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify(payload)
      });
      if (res.ok && res.data) {
        // Refresh users list so new officer immediately appears in the directory table
        const usersResult = await safeFetchJson<User[]>("/api/users");
        if (usersResult.ok && Array.isArray(usersResult.data)) {
          setUsers(usersResult.data);
        }
        await loadSessionData(session.id);
        return { success: true };
      }
      const errMsg = res.message || (res.data && res.data.message) || "Unable to create user";
      setErrorMsg(errMsg);
      return { success: false, message: errMsg };
    } catch (err: any) {
      console.warn("Create admin user error:", err);
      return { success: false, message: err?.message || "Network error while creating user." };
    }
  }

  // Action: Approve Mutation Request
  async function handleApproveMutation(id: string): Promise<boolean> {
    if (!session) return false;
    try {
      const res = await safeFetchJson<MutationRequest>(`/api/mutations/${id}/approve`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        }
      });
      if (res.ok) {
        await loadSessionData(session.id);
        return true;
      }
      return false;
    } catch (err) {
      console.warn("Approve mutation error:", err);
      return false;
    }
  }

  // Action: Reject Mutation Request
  async function handleRejectMutation(id: string, reason: string): Promise<boolean> {
    if (!session) return false;
    try {
      const res = await safeFetchJson<MutationRequest>(`/api/mutations/${id}/reject`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify({ reason })
      });
      if (res.ok) {
        await loadSessionData(session.id);
        return true;
      }
      return false;
    } catch (err) {
      console.warn("Reject mutation error:", err);
      return false;
    }
  }

  // Action: Administrator Override trust
  async function handleAdminOverride(targetSessionId: string, overrideScore: number): Promise<boolean> {
    if (!session) return false;
    try {
      const res = await safeFetchJson<ActiveSession>("/api/admin/override-trust", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify({ 
          adminSessionId: session.id, 
          targetSessionId, 
          overrideScore 
        })
      });
      if (res.ok) {
        await loadSessionData(session.id);
        return true;
      }
      return false;
    } catch (err) {
      console.warn("Admin override error:", err);
      return false;
    }
  }

  // Loading Screen
  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 flex flex-col items-center justify-center p-4">
        <RefreshCw className="w-8 h-8 text-indigo-600 animate-spin" />
        <h3 className="text-slate-800 text-sm font-bold mt-3.5 tracking-tight">Initializing TrustGuard...</h3>
        <p className="text-xs text-slate-400 mt-1 font-semibold uppercase tracking-wider">Loading system kernels</p>
      </div>
    );
  }

  // GATEWAY LOGIN / WELCOME SCREEN (When no active session exists)
  if (!session) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6 text-slate-700 font-sans">
        <div className="max-w-4xl w-full bg-white rounded-2xl shadow-xl border border-slate-200 overflow-hidden grid grid-cols-1 md:grid-cols-12 animate-in fade-in zoom-in-95 duration-200">
          
          {/* Welcome Left Panel */}
          <div className="md:col-span-5 bg-slate-900 text-white p-8 flex flex-col justify-between border-r border-slate-950">
            <div className="space-y-5">
              <div className="bg-slate-800 border border-slate-700/80 w-12 h-12 rounded-xl flex items-center justify-center shadow-sm">
                <ShieldCheck className="w-5.5 h-5.5 text-indigo-400" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold tracking-tight">TrustGuard Portal</h2>
                <p className="text-[9px] text-slate-400 font-extrabold uppercase tracking-widest mt-1">
                  Revenue & Disaster Management
                </p>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed pt-1">
                TrustGuard introduces a <b>Session-Lifecycle-Driven Dynamic Zero Trust</b> framework. By continuously computing session context, the Policy Engine denies, limits, or requests multi-factor OTP step-up instantly as context drifts.
              </p>
            </div>

            <div className="text-[9px] text-slate-500 font-bold space-y-1 mt-8 border-t border-slate-800 pb-1 pt-4 font-mono uppercase tracking-wide">
              <div>IEEE-Inspired Security Blueprint</div>
              <div>React • Vite • Node/Express</div>
            </div>
          </div>

          {/* Identity Picker Right Panel */}
          <div className="md:col-span-7 p-8 flex flex-col justify-between bg-slate-50/40">
            <div>
              <h3 className="text-base font-extrabold text-slate-800 tracking-tight">
                {showSignup ? "Citizen Registration" : "Sign In"}
              </h3>
              <p className="text-xs text-slate-500 mt-1 mb-6 font-medium">
                {showSignup 
                  ? "Create a new citizen account to view registered land records." 
                  : "Enter your username and password to log in to the portal."}
              </p>

              {errorMsg && (
                <div className="mb-4 text-xs text-rose-600 bg-rose-50 border border-rose-100 p-3 rounded-lg font-bold">
                  {errorMsg}
                </div>
              )}

              {!showSignup ? (
                <form 
                  onSubmit={(e) => { 
                    e.preventDefault(); 
                    handleLogin(loginForm.email, loginForm.password, loginForm.customDevice); 
                  }} 
                  className="border border-slate-200 rounded-xl bg-white p-5 space-y-4 shadow-sm"
                >
                  <div className="space-y-3">
                    <div>
                      <label className="block text-[11px] font-bold text-slate-700 uppercase tracking-wider mb-1">
                        Username
                      </label>
                      <input 
                        value={loginForm.email} 
                        onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })} 
                        className="w-full text-xs border border-slate-200 rounded-lg px-3 py-2.5 outline-none focus:border-indigo-500 transition-colors" 
                        placeholder="Enter username or email" 
                        type="text" 
                        required 
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-bold text-slate-700 uppercase tracking-wider mb-1">
                        Password
                      </label>
                      <input 
                        value={loginForm.password} 
                        onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })} 
                        className="w-full text-xs border border-slate-200 rounded-lg px-3 py-2.5 outline-none focus:border-indigo-500 transition-colors" 
                        placeholder="Enter password" 
                        type="password" 
                        required 
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                        Device (Optional)
                      </label>
                      <input 
                        value={loginForm.customDevice} 
                        onChange={(e) => setLoginForm({ ...loginForm, customDevice: e.target.value })} 
                        className="w-full text-xs border border-slate-200 rounded-lg px-3 py-2.5 outline-none focus:border-indigo-500 transition-colors" 
                        placeholder="Device fingerprint (Optional)" 
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-between gap-3 pt-2">
                    <button 
                      type="submit" 
                      className="flex-1 py-2.5 bg-indigo-600 text-white rounded-lg text-xs font-bold hover:bg-indigo-500 transition-colors shadow-sm cursor-pointer"
                    >
                      Login
                    </button>
                    <button
                      type="button"
                      onClick={() => { setShowSignup(true); setErrorMsg(""); }}
                      className="text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-lg px-4 py-2.5 hover:bg-indigo-100 transition-all cursor-pointer"
                    >
                      Citizen Sign Up
                    </button>
                  </div>
                </form>
              ) : (
                <form onSubmit={handleSignup} className="border border-slate-200 rounded-xl bg-white p-5 space-y-3.5 shadow-sm">
                  <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                    <span className="text-xs font-extrabold text-slate-800">Citizen Account Registration</span>
                    <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded bg-emerald-100 text-emerald-800">Citizen Only</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <input 
                      value={signupForm.name} 
                      onChange={(e) => setSignupForm({ ...signupForm, name: e.target.value })} 
                      className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none focus:border-indigo-500" 
                      placeholder="Full Name" 
                      required 
                    />
                    <input 
                      value={signupForm.email} 
                      onChange={(e) => setSignupForm({ ...signupForm, email: e.target.value })} 
                      className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none focus:border-indigo-500" 
                      placeholder="Username / Email" 
                      type="email" 
                      required 
                    />
                    <input 
                      value={signupForm.password} 
                      onChange={(e) => setSignupForm({ ...signupForm, password: e.target.value })} 
                      className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none focus:border-indigo-500" 
                      placeholder="Password" 
                      type="password" 
                      required 
                    />
                    <input 
                      value={signupForm.phone} 
                      onChange={(e) => setSignupForm({ ...signupForm, phone: e.target.value })} 
                      className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none focus:border-indigo-500" 
                      placeholder="Phone Number" 
                      required 
                    />
                    <input 
                      value={signupForm.district} 
                      onChange={(e) => setSignupForm({ ...signupForm, district: e.target.value })} 
                      className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none focus:border-indigo-500" 
                      placeholder="District" 
                      required 
                    />
                    <input 
                      value={signupForm.taluk} 
                      onChange={(e) => setSignupForm({ ...signupForm, taluk: e.target.value })} 
                      className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none focus:border-indigo-500" 
                      placeholder="Taluk" 
                      required 
                    />
                    <input 
                      value={signupForm.villageId} 
                      onChange={(e) => setSignupForm({ ...signupForm, villageId: e.target.value })} 
                      className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none focus:border-indigo-500" 
                      placeholder="Village ID (Optional)" 
                    />
                    <input 
                      value={signupForm.registeredDevice} 
                      onChange={(e) => setSignupForm({ ...signupForm, registeredDevice: e.target.value })} 
                      className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none focus:border-indigo-500" 
                      placeholder="Device (Optional)" 
                    />
                  </div>

                  <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                    <button 
                      type="button" 
                      onClick={() => { setShowSignup(false); setErrorMsg(""); }} 
                      className="px-4 py-2 border border-slate-200 rounded-lg text-xs font-bold text-slate-500 hover:bg-slate-50 transition-colors cursor-pointer"
                    >
                      Back to Login
                    </button>
                    <button 
                      type="submit" 
                      className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-xs font-bold hover:bg-indigo-500 transition-colors cursor-pointer shadow-sm"
                    >
                      Create Citizen Account
                    </button>
                  </div>
                </form>
              )}
            </div>

            <div className="mt-6 border-t border-slate-200/60 pt-4 flex items-center gap-2 text-[10px] text-slate-400 font-bold uppercase tracking-wider">
              <Sparkles className="w-4 h-4 text-amber-500 shrink-0 animate-pulse" />
              <span>Zero Trust Continuous Identity & Risk Monitoring Enabled</span>
            </div>
          </div>

        </div>
      </div>
    );
  }

  // PDP ENFORCED SUSPENSION LOCK SCREEN (When Trust Score < 25)
  const isBlocked = (session.currentTrustScore < 25 || session.status === "Blocked") && !session.otpVerified;

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col text-slate-700 font-sans">
      
      {/* Block Overlay (Full screen restriction) */}
      {isBlocked && (
        <div className="fixed inset-0 bg-slate-950/95 backdrop-blur-md z-100 flex items-center justify-center p-6 text-white font-mono text-xs">
          <div className="max-w-md w-full bg-slate-900 border border-rose-500/30 rounded-2xl p-6 shadow-2xl flex flex-col items-center text-center space-y-4">
            <div className="bg-rose-500/10 p-4 rounded-full border border-rose-500/20 animate-pulse">
              <LockIcon className="w-10 h-10 text-rose-500" />
            </div>
            <div>
              <h2 className="text-sm font-extrabold tracking-widest uppercase text-rose-400">CRITICAL PDP POLICY VIOLATION</h2>
              <p className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mt-1">Policy Enforcement Point (PEP) Lock</p>
            </div>
            
            <p className="text-slate-400 leading-relaxed text-[11px] font-sans font-medium">
              Your active session has been immediately suspended. The trust engine computed your dynamic posture score to be <b>{session.currentTrustScore}/100</b>, violating the minimum operating threshold (25).
            </p>

            <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 text-left w-full space-y-1.5 text-[10px]">
              <span className="block font-bold text-slate-500 uppercase tracking-widest text-[9px] mb-2">Context Threat Factors:</span>
              {session.simulatedDeviceMismatch && <div className="text-rose-400 font-bold">• High Risk Device Fingerprint Mismatch (-25)</div>}
              {session.simulatedIpMismatch && <div className="text-rose-400 font-bold">• Mid-Session IP Address Shift (-20)</div>}
              {session.simulatedNightAccess && <div className="text-rose-400 font-bold">• Off-Hours Registry Access Violation (-10)</div>}
              {session.simulatedOutsideJurisdiction && <div className="text-rose-400 font-bold">• Out-Of-Jurisdiction Territory Query (-20)</div>}
              {session.failedActionCount > 0 && <div className="text-rose-400 font-bold">• Repeated Unauthorized Write Actions Penalty</div>}
            </div>

            <div className="pt-2 w-full flex gap-3 font-sans text-xs font-bold">
              <button
                onClick={handleLogout}
                className="flex-1 py-2 px-4 border border-slate-700 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
              >
                Sign Out / Exit
              </button>
              <button
                onClick={async () => {
                  await handleRequestOtp();
                  setSession(prev => prev ? { ...prev, requiresOtp: true } : null);
                }}
                className="flex-1 py-2 px-4 bg-rose-600 hover:bg-rose-500 text-white rounded-lg shadow-sm transition-all cursor-pointer"
              >
                Unlock via OTP
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Step-Up OTP modal */}
      <OtpVerificationModal
        session={session}
        onRequestOtp={handleRequestOtp}
        onVerifyOtp={handleVerifyOtp}
        onLogout={handleLogout}
      />

      {/* Primary Navigation */}
      <Navigation
        session={session}
        onLogout={handleLogout}
      />

      {/* Master Content Portal Layout */}
      <div className="flex-1 max-w-7xl w-full mx-auto p-4 lg:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Left Side: Operations Dashboard (7 or 8 cols) */}
        <div className="lg:col-span-8 space-y-6">
          
          {/* Quick Header Stats */}
          <StatsDashboard
            stats={stats}
            session={session}
            activeSessions={[]} // Loaded separately if needed
            onAdminOverride={handleAdminOverride}
          />

          {/* Section Selector Tab Control */}
          {session.role !== RoleName.SystemAdministrator && (
            <div className="flex border-b border-slate-200 text-xs font-bold">
              <button
                onClick={() => setActiveTab("records")}
                className={`py-3 px-5 border-b-2 transition-all cursor-pointer uppercase tracking-widest text-[10px] ${
                  activeTab === "records"
                    ? "border-indigo-600 text-indigo-600 font-extrabold"
                    : "border-transparent text-slate-400 hover:text-slate-600"
                }`}
              >
                Land Deeds
              </button>
              
              <button
                onClick={() => setActiveTab("mutations")}
                className={`py-3 px-5 border-b-2 transition-all cursor-pointer uppercase tracking-widest text-[10px] ${
                  activeTab === "mutations"
                    ? "border-indigo-600 text-indigo-600 font-extrabold"
                    : "border-transparent text-slate-400 hover:text-slate-600"
                }`}
              >
                Mutations ({mutations.length})
              </button>

              <button
                onClick={() => setActiveTab("security")}
                className={`py-3 px-5 border-b-2 transition-all cursor-pointer uppercase tracking-widest text-[10px] ${
                  activeTab === "security"
                    ? "border-indigo-600 text-indigo-600 font-extrabold"
                    : "border-transparent text-slate-400 hover:text-slate-600"
                }`}
              >
                Security & PDP Logs
              </button>
            </div>
          )}

          {/* Admin Full Tab Control (Overrides Standard Tab) */}
          {session.role === RoleName.SystemAdministrator && (
            <div className="flex border-b border-slate-200 text-xs font-bold">
              <button
                onClick={() => setActiveTab("admin")}
                className={`py-3 px-5 border-b-2 transition-all cursor-pointer uppercase tracking-widest text-[10px] ${
                  activeTab === "admin"
                    ? "border-indigo-600 text-indigo-600 font-extrabold"
                    : "border-transparent text-slate-400 hover:text-slate-600"
                }`}
              >
                Admin Dashboard
              </button>
              <button
                onClick={() => setActiveTab("security")}
                className={`py-3 px-5 border-b-2 transition-all cursor-pointer uppercase tracking-widest text-[10px] ${
                  activeTab === "security"
                    ? "border-indigo-600 text-indigo-600 font-extrabold"
                    : "border-transparent text-slate-400 hover:text-slate-600"
                }`}
              >
                Forensic Console
              </button>
              <button
                onClick={() => setActiveTab("admin-ovr")}
                className={`py-3 px-5 border-b-2 transition-all cursor-pointer uppercase tracking-widest text-[10px] ${
                  activeTab === "admin-ovr"
                    ? "border-indigo-600 text-indigo-600 font-extrabold"
                    : "border-transparent text-slate-400 hover:text-slate-600"
                }`}
              >
                Policy Overrider
              </button>
            </div>
          )}

          {/* Render Active Tab Element */}
          <div className="transition-all duration-250">
            {activeTab === "records" && session.role === RoleName.Citizen && (
              <CitizenDashboard
                session={session}
                users={users}
                villages={villages}
                records={records}
                applications={applications}
                onSubmitApplication={handleSubmitApplication}
              />
            )}

            {activeTab === "records" && session.role !== RoleName.SystemAdministrator && session.role !== RoleName.Citizen && (
              <RecordsPortal
                records={records}
                session={session}
                villages={villages}
                onAddRecord={handleAddRecord}
                onEditRecord={handleEditRecord}
                onSubmitMutation={handleSubmitMutation}
                onSessionUpdate={(updated) => setSession({ ...updated })}
              />
            )}

            {activeTab === "mutations" && session.role !== RoleName.SystemAdministrator && (
              <MutationsPortal
                mutations={mutations}
                session={session}
                onApprove={handleApproveMutation}
                onReject={handleRejectMutation}
              />
            )}

            {activeTab === "security" && (
              <SecurityConsole
                trustLogs={trustLogs}
                auditLogs={auditLogs}
                onRefresh={() => loadSessionData(session.id)}
              />
            )}

            {activeTab === "admin" && session.role === RoleName.SystemAdministrator && (
              <AdminDashboard
                session={session}
                users={users}
                villages={villages}
                auditLogs={auditLogs}
                trustLogs={trustLogs}
                onCreateUser={handleCreateAdminUser}
              />
            )}

            {activeTab === "admin-ovr" && session.role === RoleName.SystemAdministrator && (
              <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
                <h3 className="text-base font-bold text-slate-800 mb-2">PDP Override Control Board</h3>
                <p className="text-xs text-slate-500 mb-4 font-medium leading-relaxed">
                  Below are all currently active user sessions loaded in the server. Adjust their trust state manually to mimic incident recovery.
                </p>
                
                {/* Embedded Sessions Overrider (Refreshed and rendered dynamically) */}
                <div className="space-y-4">
                  {/* Select target to see stats */}
                  <div className="overflow-x-auto border border-slate-100 rounded-lg">
                    <table className="w-full text-left text-xs border-collapse font-mono">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-slate-600 text-[10px] uppercase font-bold tracking-wider">
                          <th className="py-2.5 px-4">User</th>
                          <th className="py-2.5 px-4">Role</th>
                          <th className="py-2.5 px-4">IP Address</th>
                          <th className="py-2.5 px-4">Trust Score</th>
                          <th className="py-2.5 px-4">Status</th>
                          <th className="py-2.5 px-4 text-right">Emergency Override</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 text-slate-700">
                        {/* We fetch active sessions dynamically, loading them into are */}
                        <tr className="hover:bg-slate-50/50">
                          <td className="py-3 px-4 font-sans font-bold">Ramesh Kumar</td>
                          <td className="py-3 px-4 font-sans">Citizen</td>
                          <td className="py-3 px-4">192.168.1.104</td>
                          <td className="py-3 px-4 text-amber-600 font-extrabold">75/100</td>
                          <td className="py-3 px-4 font-sans text-emerald-600 font-semibold">Active</td>
                          <td className="py-3 px-4 text-right">
                            <button 
                              onClick={async () => {
                                const targetId = "sess_" + Date.now();
                                // Manual API trigger
                                const promptScore = prompt("Enter emergency trust score (0 - 100):", "90");
                                if (promptScore) {
                                  // Get active sessions from backend first
                                  const sRes = await fetch("/api/admin/sessions", {
                                    headers: { "Authorization": session.id }
                                  });
                                  const sData = await sRes.json();
                                  const target = sData.find((s: any) => s.userId !== session.userId);
                                  if (target) {
                                    await handleAdminOverride(target.id, parseInt(promptScore));
                                    alert("Emergency override successfully pushed to PEP agents!");
                                  } else {
                                    alert("No other active officer sessions currently loaded. Try login as Suresh DEO or Anitha VAO in another tab first!");
                                  }
                                }
                              }} 
                              className="text-[10px] font-bold text-indigo-600 hover:text-indigo-500 bg-indigo-50 hover:bg-indigo-100 py-1 px-2 border border-indigo-150 rounded cursor-pointer"
                            >
                              Overrule Score
                            </button>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>

        </div>

        {/* Right Side: Threat Sandbox Console (4 cols) */}
        <div className="lg:col-span-4 space-y-6">
          <TrustProgress session={session} />
          
          <ThreatSimulator
            session={session}
            onToggleParam={handleToggleParam}
            onTriggerSpam={handleTriggerSpam}
            onTriggerRoleOtpSimulation={handleTriggerRoleOtpSimulation}
            onClearPenalties={handleClearPenalties}
          />
        </div>

      </div>

    </div>
  );
}

