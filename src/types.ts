/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export enum RoleName {
  Citizen = "Citizen / Land Owner",
  DataEntryOperator = "Data Entry Operator",
  VillageAdministrativeOfficer = "VAO / Village Officer",
  RevenueInspector = "Revenue Inspector (RI)",
  DeputyTahsildar = "Deputy Tahsildar",
  Tahsildar = "Tahsildar",
  SystemAdministrator = "System Administrator"
}

export enum JurisdictionLevel {
  Global = "Global",
  District = "District",
  Taluk = "Taluk",
  Village = "Village",
  OwnRecord = "Own Record",
  None = "None"
}

export interface Role {
  id: string;
  name: RoleName;
  jurisdiction: JurisdictionLevel;
  basePermissions: string[];
}

export interface PropertyAsset {
  id: string;
  surveyNumber: string;
  ownerName: string;
  ownerPhone: string;
  villageId: string;
  villageName: string;
  area: string;
  landType: "Agricultural" | "Commercial" | "Residential" | "Forest";
  status: "Active" | "Mutation Pending" | "Disputed";
  pattaNumber?: string;
  chittaNumber?: string;
  pattaDocumentPath?: string;
  chittaDocumentPath?: string;
  fmbCopyPath?: string;
}

export interface User {
  id: string;
  name: string;
  email: string;
  password?: string;
  passwordHash?: string;
  roleName: RoleName;
  phone: string;
  assignedJurisdiction: {
    district?: string;
    taluk?: string;
    villageId?: string; // village PK
  };
  registeredDevice: string; // Known device fingerprint
  properties?: PropertyAsset[];
  status?: "Active" | "Suspended" | "Disabled";
}

export interface Village {
  id: string;
  name: string;
  taluk: string;
  district: string;
}

export enum ApplicationStatus {
  Submitted = "SUBMITTED",
  DataEntryVerification = "DATA_ENTRY_VERIFICATION",
  VaoVerification = "VAO_VERIFICATION",
  RevenueInspectorVerification = "REVENUE_INSPECTOR_VERIFICATION",
  DeputyTahsildarReview = "DEPUTY_TAHSILDAR_REVIEW",
  TahsildarApproval = "TAHSILDAR_APPROVAL",
  Approved = "APPROVED",
  Rejected = "REJECTED"
}

export interface Application {
  id: string;
  applicantName: string;
  applicantEmail: string;
  applicantId: string;
  landRecordId: string;
  surveyNumber: string;
  applicationType: "Patta" | "Chitta" | "Land Transfer";
  reason: string;
  supportingDocumentReference?: string;
  submissionDate: string;
  status: ApplicationStatus | string;
  district?: string;
  taluk?: string;
  village?: string;
}

export interface LandRecord {
  id: string;
  surveyNumber: string;
  ownerName: string;
  ownerPhone: string;
  villageId: string;
  villageName: string;
  area: string; // e.g., "2.4 Acres"
  landType: "Agricultural" | "Commercial" | "Residential" | "Forest";
  documentPath: string;
  documentTitle?: string;
  lastModifiedBy: string; // User ID or name
  lastModifiedAt: string;
  status: "Active" | "Mutation Pending" | "Disputed";
  pattaNumber?: string;
  chittaNumber?: string;
  pattaDocumentPath?: string;
  chittaDocumentPath?: string;
  fmbCopyPath?: string;
  documentClassification?: "Public" | "Restricted" | "Confidential";
  verificationStatus?: "Verified" | "Pending Verification" | "Rejected";
  documentHash?: string;
  issuedDate?: string;
  district?: string;
  taluk?: string;
}

export interface MutationRequest {
  id: string;
  recordId: string;
  surveyNumber: string;
  ownerName: string;
  villageName: string;
  area: string;
  landType: string;
  currentOwner: string;
  proposedOwner: string;
  requestedBy: string; // User ID (Citizen or DEO)
  requestedByName: string;
  requestType: "Transfer" | "Division" | "Correction";
  status: "Pending VAO" | "Pending RI" | "Pending Deputy Tahsildar" | "Pending Tahsildar" | "Approved" | "Rejected";
  approved?: boolean; // true when the request has been approved by the VAO and handed to the next officer
  approvedBy?: string; // Tahsildar or DT User Name
  approvalDate?: string;
  remarks: string;
  createdAt: string;
}

export enum TrustAction {
  FullAccess = "Full Access",
  ReadOnly = "Read-Only",
  OtpRequired = "OTP Required",
  Blocked = "Session Blocked"
}

export interface ActiveSession {
  id: string;
  userId: string;
  userName: string;
  userEmail?: string;
  role: RoleName;
  deviceFingerprint: string;
  ipAddress: string;
  loginTime: string;
  lastActivityTime: string;
  currentTrustScore: number;
  status: "Active" | "Blocked" | "Expired";
  token?: string;
  // Context simulated overrides
  simulatedDeviceMismatch: boolean;
  simulatedIpMismatch: boolean;
  simulatedNightAccess: boolean;
  simulatedOutsideJurisdiction: boolean;
  simulatedSpamTriggered: boolean;
  simulatedIdleTriggered: boolean;
  failedActionCount: number;
  otpVerified: boolean;
  realLoginIp?: string;
  realLoginUserAgent?: string;
  initialAuthenticatedIp?: string;
  currentRequestIp?: string;
}

export interface TrustLog {
  id: string;
  sessionId: string;
  eventType: string;
  trustChangeValue: number;
  resultingTrustScore: number;
  timestamp: string;
}

export interface AuditLog {
  id: string;
  userId: string;
  userName: string;
  role: RoleName;
  actionPerformed: string;
  resourceAccessed: string;
  trustScoreAtAction: number;
  decision: "ALLOWED" | "DENIED" | "STEP-UP OTP" | "TERMINATED" | "LIMITED ACCESS" | "RATE_LIMITED";
  timestamp: string;
  // Forensic audit trail fields
  previousTrustScore?: number;
  currentTrustScore?: number;
  riskLevel?: string;
  reasons?: string[];
  ipAddress?: string;
  location?: string;
  device?: string;
  
  // Phase 16: New ML & Hybrid Trust Fields
  ruleRisk?: number;
  ruleTrust?: number;
  isolationForestScore?: number;
  normalizedAnomalyScore?: number;
  mlRisk?: number;
  finalTrustScore?: number;
  accessDecision?: string;
  triggeredRules?: string[];
  mlStatus?: string;
  
  // Phase 16: Session Behavior Features
  loginHour?: number;
  recordsViewed?: number;
  downloadsCount?: number;
  requestsPerMinute?: number;
  failedOperations?: number;
  sessionDurationMinutes?: number;
  distinctDocumentsCount?: number;
  documentSensitivity?: number;

  emailAlertSent?: boolean;
  emailAlertDetails?: {
    alertId?: string;
    recipient?: string;
    subject?: string;
    status?: "SENT" | "FAILED" | "SUPPRESSED_COOLDOWN" | "SKIPPED_POLICY" | "SIMULATED_LOGGED";
    error?: string;
    sentAt?: string;
  };
  policyAction?: string;
}

export interface SecurityAlert {
  id: string;
  userId: string;
  userName: string;
  userEmail: string;
  userRole: RoleName | string;
  previousTrustScore: number;
  currentTrustScore: number;
  riskLevel: string;
  reasons: string[];
  ipAddress: string;
  location: string;
  deviceFingerprint: string;
  policyAction: string;
  timestamp: string;
  emailAlertSent: boolean;
  emailRecipient: string;
  emailStatus: "SENT" | "FAILED" | "SUPPRESSED_COOLDOWN" | "SIMULATED_LOGGED";
  emailError?: string;
  requestResource?: string;
  status?: "NEW" | "INVESTIGATING" | "RESOLVED";
  investigatedBy?: string;
  resolutionNotes?: string;
}

export interface SystemStats {
  totalRecords: number;
  activeSessionsCount: number;
  pendingMutations: number;
  securityIncidentsCount: number;
  totalUsers?: number;
  totalDocumentAccessAttempts?: number;
  successfulAccessAttempts?: number;
  deniedAccessAttempts?: number;
  highRiskUsersCount?: number;
  criticalSecurityIncidents?: number;
  averageTrustScore?: number;
  recentTrustScoreChanges?: number;
  suspiciousAccessEvents?: number;
  anomalyDetectionCount?: number;
  averageAnomalyScore?: number;
}
