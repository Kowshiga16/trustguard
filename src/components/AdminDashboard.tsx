import React, { useMemo, useState, useEffect } from "react";
import { 
  ShieldCheck, UserPlus, Users, Activity, Bell, FileText, RefreshCw, 
  AlertTriangle, ShieldAlert, CheckCircle, Search, Mail, Check, MessageSquare
} from "lucide-react";
import { ActiveSession, RoleName, User, Village } from "../types";

interface AdminDashboardProps {
  session: ActiveSession;
  users: User[];
  villages: Village[];
  auditLogs: any[];
  trustLogs: any[];
  onCreateUser: (payload: any) => Promise<{ success: boolean; message?: string } | boolean>;
}

const adminRoleOptions = [
  { value: RoleName.DataEntryOperator, label: "DATA_ENTRY_OPERATOR" },
  { value: RoleName.VillageAdministrativeOfficer, label: "VAO" },
  { value: RoleName.RevenueInspector, label: "REVENUE_INSPECTOR" },
  { value: RoleName.DeputyTahsildar, label: "DEPUTY_TAHSILDAR" },
  { value: RoleName.Tahsildar, label: "TAHSILDAR" }
];

export default function AdminDashboard({ session, users, villages, auditLogs, trustLogs, onCreateUser }: AdminDashboardProps) {
  const [form, setForm] = useState({
    name: "",
    email: "",
    phone: "",
    roleName: RoleName.DataEntryOperator,
    district: "Kancheepuram",
    taluk: "Tambaram",
    villageId: "v1",
    password: "",
    registeredDevice: "Officer_Workstation"
  });
  const [error, setError] = useState<string>("");
  const [success, setSuccess] = useState<string>("");

  // Alert management state
  const [alerts, setAlerts] = useState<any[]>([]);
  const [alertFilter, setAlertFilter] = useState("all");
  const [updatingAlertId, setUpdatingAlertId] = useState<string | null>(null);
  const [resolutionNote, setResolutionNote] = useState("");
  const [selectedAlertForNote, setSelectedAlertForNote] = useState<string | null>(null);

  const fetchAlerts = async () => {
    try {
      const res = await fetch("/api/security/alerts");
      if (res.ok) {
        const data = await res.json();
        setAlerts(data);
      }
    } catch (err) {
      console.warn("Error fetching alerts:", err);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleUpdateStatus = async (alertId: string, newStatus: "NEW" | "INVESTIGATING" | "RESOLVED", notes?: string) => {
    setUpdatingAlertId(alertId);
    try {
      const res = await fetch(`/api/security/alerts/${alertId}/status`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Authorization": session.id
        },
        body: JSON.stringify({ status: newStatus, notes })
      });
      if (res.ok) {
        await fetchAlerts();
        setSelectedAlertForNote(null);
        setResolutionNote("");
      }
    } catch (err) {
      console.error("Failed to update alert status:", err);
    } finally {
      setUpdatingAlertId(null);
    }
  };

  const revenueUsers = useMemo(() => users.filter(u => [
    RoleName.DataEntryOperator,
    RoleName.VillageAdministrativeOfficer,
    RoleName.RevenueInspector,
    RoleName.DeputyTahsildar,
    RoleName.Tahsildar
  ].includes(u.roleName)), [users]);

  function handleVillageSelect(vId: string) {
    const selected = villages.find(v => v.id === vId);
    if (selected) {
      setForm(prev => ({
        ...prev,
        villageId: vId,
        district: selected.district,
        taluk: selected.taluk
      }));
    } else {
      setForm(prev => ({ ...prev, villageId: vId }));
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!form.name || !form.email || !form.phone || !form.roleName || !form.district || !form.taluk || !form.password) {
      setError("Please complete all required fields (Name, Email, Phone, Role, District, Taluk, Password).");
      return;
    }

    const payload = {
      name: form.name.trim(),
      email: form.email.trim(),
      phone: form.phone.trim(),
      roleName: form.roleName,
      password: form.password,
      assignedJurisdiction: {
        district: form.district.trim(),
        taluk: form.taluk.trim(),
        villageId: form.villageId || undefined
      },
      registeredDevice: form.registeredDevice || "Officer_Workstation"
    };

    const res = await onCreateUser(payload);
    const isSuccess = typeof res === "boolean" ? res : res.success;
    const errorMsg = typeof res === "object" && res.message ? res.message : "Unable to create the revenue department user.";

    if (!isSuccess) {
      setError(errorMsg);
      return;
    }

    setSuccess(`User "${form.name}" (${form.roleName}) created successfully!`);
    setForm({
      name: "",
      email: "",
      phone: "",
      roleName: RoleName.DataEntryOperator,
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1",
      password: "",
      registeredDevice: "Officer_Workstation"
    });
  }

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-indigo-600">
              <ShieldCheck className="w-5 h-5" />
              <span className="text-xs font-black uppercase tracking-widest">System Admin Dashboard</span>
            </div>
            <h2 className="text-xl font-black text-slate-900 mt-2">Revenue User Administration</h2>
          </div>
          <div className="flex items-center gap-2 text-xs font-bold text-slate-500">
            <Activity className="w-4 h-4 text-emerald-500" /> Access: {session.role}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-5 bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center gap-2 mb-4">
            <UserPlus className="w-4 h-4 text-indigo-600" />
            <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide">Add User</h3>
          </div>

          {error && <div className="mb-3 rounded-lg border border-rose-200 bg-rose-50 text-rose-700 px-3 py-2 text-xs font-bold">{error}</div>}
          {success && <div className="mb-3 rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-700 px-3 py-2 text-xs font-bold">{success}</div>}

          <form onSubmit={submit} className="grid grid-cols-1 gap-3">
            <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none" placeholder="Full Name" required />
            <input value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none" placeholder="Email" type="email" required />
            <input value={form.phone} onChange={e => setForm({ ...form, phone: e.target.value })} className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none" placeholder="Phone" required />

            <select value={form.roleName} onChange={e => setForm({ ...form, roleName: e.target.value as RoleName })} className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none" required>
              {adminRoleOptions.map(option => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>

            <input value={form.district} onChange={e => setForm({ ...form, district: e.target.value })} className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none" placeholder="District" required />
            <input value={form.taluk} onChange={e => setForm({ ...form, taluk: e.target.value })} className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none" placeholder="Taluk" required />

            <select value={form.villageId} onChange={e => handleVillageSelect(e.target.value)} className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none">
              <option value="">Select Village (Auto-fills Taluk & District)</option>
              {villages.map(v => (
                <option key={v.id} value={v.id}>{v.name} ({v.taluk})</option>
              ))}
            </select>

            <input value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} className="text-xs border border-slate-200 rounded-lg px-3 py-2 outline-none" placeholder="Temporary Password" type="password" required />

            <div className="flex justify-end gap-2">
              <button type="button" onClick={() => setForm({ ...form, name: "", email: "", phone: "", district: "", taluk: "", villageId: "", password: "" })} className="px-4 py-2 border border-slate-200 rounded-lg text-xs font-bold text-slate-500 hover:bg-slate-50">
                Reset
              </button>
              <button type="submit" className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-xs font-bold hover:bg-indigo-500">
                Create User
              </button>
            </div>
          </form>
        </section>

        <section className="lg:col-span-7 bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4 text-indigo-600" />
              <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide">User Directory</h3>
            </div>
            <span className="text-[10px] font-black text-slate-500">{revenueUsers.length} Active Revenue Roles</span>
          </div>

          <div className="overflow-x-auto mt-4 border border-slate-100 rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50">
                <tr className="text-[10px] uppercase tracking-wide text-slate-500">
                  <th className="py-3 px-3">Name</th>
                  <th className="py-3 px-3">Email</th>
                  <th className="py-3 px-3">Role</th>
                  <th className="py-3 px-3">Jurisdiction</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {revenueUsers.map(user => (
                  <tr key={user.id} className="hover:bg-slate-50">
                    <td className="py-2 px-3 font-bold text-slate-800">{user.name}</td>
                    <td className="py-2 px-3 text-slate-600">{user.email}</td>
                    <td className="py-2 px-3">
                      <span className="rounded-full bg-indigo-50 border border-indigo-100 px-2 py-1 text-[10px] font-black text-indigo-700">{user.roleName}</span>
                    </td>
                    <td className="py-2 px-3 text-slate-600">
                      {user.assignedJurisdiction?.district || "-"} / {user.assignedJurisdiction?.taluk || "-"} / {user.assignedJurisdiction?.villageId || "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {/* Security Incident & Alert Investigation Center */}
      <section className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-600" />
            <div>
              <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide">
                Security Incidents & Forensic Alerts Investigation
              </h3>
              <p className="text-[11px] text-slate-500">
                Track, investigate, and resolve Zero Trust behavioral alerts with audit log verification
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={alertFilter}
              onChange={(e) => setAlertFilter(e.target.value)}
              className="text-xs font-bold border border-slate-250 bg-slate-50 rounded-lg px-2.5 py-1.5 text-slate-700 cursor-pointer"
            >
              <option value="all">All Alerts ({alerts.length})</option>
              <option value="NEW">New Unreviewed</option>
              <option value="INVESTIGATING">Under Investigation</option>
              <option value="RESOLVED">Resolved Incidents</option>
            </select>

            <button
              onClick={fetchAlerts}
              className="p-1.5 rounded-lg border border-slate-250 text-slate-500 hover:text-slate-900 transition-colors"
              title="Refresh Alerts"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Alerts List */}
        <div className="space-y-3">
          {alerts
            .filter((a) => alertFilter === "all" || (a.status || "NEW") === alertFilter)
            .map((alert) => {
              const status = alert.status || "NEW";
              const isUpdating = updatingAlertId === alert.id;

              return (
                <div key={alert.id} className="border border-slate-200 rounded-xl p-4 bg-slate-50/50 space-y-3">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          alert.severity === "CRITICAL" ? "bg-rose-100 text-rose-800 border border-rose-200" :
                          alert.severity === "HIGH RISK" ? "bg-orange-100 text-orange-800 border border-orange-200" :
                          "bg-amber-100 text-amber-800 border border-amber-200"
                        }`}>
                          {alert.severity}
                        </span>

                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          status === "NEW" ? "bg-amber-100 text-amber-800 border border-amber-300" :
                          status === "INVESTIGATING" ? "bg-blue-100 text-blue-800 border border-blue-300" :
                          "bg-emerald-100 text-emerald-800 border border-emerald-300"
                        }`}>
                          Status: {status}
                        </span>

                        {alert.emailSent && (
                          <span className="inline-flex items-center gap-1 text-[9px] font-bold text-sky-700 bg-sky-50 border border-sky-200 px-1.5 py-0.5 rounded">
                            <Mail className="w-2.5 h-2.5" /> Alert Dispatched
                          </span>
                        )}
                      </div>

                      <div className="text-xs font-bold text-slate-900 pt-1">
                        Affected Officer: <span className="text-indigo-700 font-extrabold">{alert.userName}</span> ({alert.userRole})
                        <span className="text-slate-400 font-normal ml-2 font-mono text-[10px]">
                          {new Date(alert.timestamp).toLocaleString()}
                        </span>
                      </div>
                    </div>

                    {/* Action buttons */}
                    <div className="flex items-center gap-2">
                      {status === "NEW" && (
                        <button
                          onClick={() => handleUpdateStatus(alert.id, "INVESTIGATING")}
                          disabled={isUpdating}
                          className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold transition-all shadow-xs cursor-pointer"
                        >
                          Mark Investigating
                        </button>
                      )}

                      {status !== "RESOLVED" && (
                        <button
                          onClick={() => {
                            if (selectedAlertForNote === alert.id) {
                              handleUpdateStatus(alert.id, "RESOLVED", resolutionNote);
                            } else {
                              setSelectedAlertForNote(alert.id);
                            }
                          }}
                          disabled={isUpdating}
                          className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-bold transition-all shadow-xs cursor-pointer flex items-center gap-1"
                        >
                          <Check className="w-3.5 h-3.5" />
                          Resolve Alert
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Forensic reasons */}
                  <div className="bg-white p-3 rounded-lg border border-slate-200 text-xs text-slate-700">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block mb-1">
                      Detected Behavioral Signals & Violations
                    </span>
                    <ul className="list-disc list-inside space-y-1 font-medium">
                      {(alert.reasons || [alert.reason || "Suspicious trust degradation"]).map((r: string, i: number) => (
                        <li key={i} className="text-slate-800">{r}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Resolution notes if open */}
                  {selectedAlertForNote === alert.id && (
                    <div className="bg-emerald-50/70 border border-emerald-200 p-3 rounded-lg space-y-2">
                      <label className="block text-[10px] font-bold text-emerald-900 uppercase tracking-wider">
                        Investigator Resolution Notes (Audit Logged)
                      </label>
                      <input
                        type="text"
                        value={resolutionNote}
                        onChange={(e) => setResolutionNote(e.target.value)}
                        placeholder="Ex: Verified authorized off-hours duty roster with Tambaram sub-taluk"
                        className="w-full text-xs px-3 py-2 bg-white border border-emerald-300 rounded-lg text-slate-800 outline-none"
                      />
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => setSelectedAlertForNote(null)}
                          className="px-3 py-1 text-xs font-bold text-slate-600 border border-slate-300 rounded-lg"
                        >
                          Cancel
                        </button>
                        <button
                          onClick={() => handleUpdateStatus(alert.id, "RESOLVED", resolutionNote)}
                          className="px-3 py-1 text-xs font-bold text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg"
                        >
                          Confirm Resolution
                        </button>
                      </div>
                    </div>
                  )}

                  {/* If resolved: show investigator info */}
                  {status === "RESOLVED" && alert.investigatedBy && (
                    <div className="text-[10px] text-emerald-800 font-medium bg-emerald-50/60 p-2 rounded border border-emerald-100">
                      Investigated and resolved by <b>{alert.investigatedBy}</b>
                      {alert.resolutionNotes && <span>: "{alert.resolutionNotes}"</span>}
                    </div>
                  )}
                </div>
              );
            })}

          {alerts.length === 0 && (
            <div className="text-center py-8 text-slate-400 text-xs font-medium border border-dashed border-slate-200 rounded-xl">
              No security incidents or trust alerts triggered. System operating within normal Zero Trust posture.
            </div>
          )}
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center gap-2 mb-4">
            <FileText className="w-4 h-4 text-indigo-600" />
            <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide">Audit Logs</h3>
          </div>
          <div className="space-y-2 max-h-80 overflow-auto">
            {auditLogs.slice(0, 8).map((a, index) => (
              <div key={index} className="border-l-2 border-indigo-200 pl-3 py-2">
                <div className="text-[10px] font-black text-slate-700">{a.actionPerformed || "Audit Event"}</div>
                <div className="text-[10px] text-slate-500">{a.timestamp || ""}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center gap-2 mb-4">
            <Bell className="w-4 h-4 text-indigo-600" />
            <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide">Security & Trust</h3>
          </div>
          <div className="space-y-2 max-h-80 overflow-auto">
            {trustLogs.slice(0, 8).map((t, index) => (
              <div key={index} className="border-l-2 border-amber-200 pl-3 py-2">
                <div className="text-[10px] font-black text-slate-700">{t.eventType || t.actionPerformed || "Trust Event"}</div>
                <div className="text-[10px] text-slate-500">{t.score || t.trustScore || ""}</div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
