/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard: Dynamic Zero Trust Access Control Configuration
 * Centralized, environment-driven configuration for:
 *  - Trust score thresholds (Low, Medium, High, Critical)
 *  - Access Modes (Full, Restricted, Read-Only, Blocked)
 *  - Explainable Risk Deductions (New Device, Diff IP, AI Anomaly, etc.)
 *  - Role-specific document access velocity and classifications
 *  - NodeMailer SMTP & Demo OTP Recipient configuration
 */

export enum RiskLevel {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL"
}

export enum AccessMode {
  FULL = "FULL",
  RESTRICTED = "RESTRICTED",
  READ_ONLY = "READ-ONLY",
  BLOCKED = "BLOCKED"
}

export interface TrustThresholds {
  lowRiskMin: number;     // 80–100: Full Access, OTP not required
  mediumRiskMin: number;  // 60–79: Restricted mode, OTP required for sensitive actions
  highRiskMin: number;    // 40–59: Read-Only mode, sensitive actions blocked
  criticalMax: number;    // < 40: Critical risk, access blocked / session challenged
}

export interface RiskDeductionsConfig {
  newDevice: number;              // default: 20
  differentIp: number;            // default: 15
  aiAnomaly: number;              // default: 25 (scaled by Isolation Forest NAS)
  rateLimitViolation: number;     // default: 15
  offHoursAccess: number;         // default: 10
  outsideJurisdiction: number;    // default: 20
  failedOperation: number;        // default: 10 per attempt
  otpRestorationBonus: number;    // default: 20
}

export interface RoleDocumentPolicy {
  maxViewsPerMinute: number;
  allowedClassifications: string[];
}

export interface AlertPolicyConfig {
  significantDropThreshold: number; // Minimum score drop to trigger alert (default: 20)
  cooldownMinutes: number;          // Deduplication cooldown window (default: 10 mins)
  alertOnLowRisk: boolean;          // Default false
  alertOnMediumRisk: boolean;       // Default false
  alertOnHighRisk: boolean;         // Default true
  alertOnCritical: boolean;         // Default true
}

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  from: string;
  demoOtpEmail: string;
  securityAlertEmail: string;
  enabled: boolean;
}

export interface MlConfig {
  serviceUrl: string;
  timeoutMs: number;
  weight: number;
}

export const trustConfig = {
  // 1. Centralized Trust Score Thresholds
  thresholds: {
    lowRiskMin: parseInt(process.env.TRUST_THRESHOLD_LOW_MIN || "80", 10),      // 80–100: LOW RISK / FULL ACCESS
    mediumRiskMin: parseInt(process.env.TRUST_THRESHOLD_MEDIUM_MIN || "60", 10), // 60–79: MEDIUM RISK / RESTRICTED
    highRiskMin: parseInt(process.env.TRUST_THRESHOLD_HIGH_MIN || "40", 10),    // 40–59: HIGH RISK / READ-ONLY
    criticalMax: parseInt(process.env.TRUST_THRESHOLD_CRITICAL_MAX || "40", 10), // < 40: CRITICAL / BLOCKED
  } as TrustThresholds,

  // 2. Centralized Explainable Risk Deductions
  deductions: {
    newDevice: parseInt(process.env.PENALTY_NEW_DEVICE || "20", 10),
    differentIp: parseInt(process.env.PENALTY_DIFFERENT_IP || "15", 10),
    aiAnomaly: parseInt(process.env.PENALTY_AI_ANOMALY || "25", 10),
    rateLimitViolation: parseInt(process.env.PENALTY_RATE_LIMIT || "15", 10),
    offHoursAccess: parseInt(process.env.PENALTY_OFF_HOURS || "10", 10),
    outsideJurisdiction: parseInt(process.env.PENALTY_JURISDICTION || "20", 10),
    failedOperation: parseInt(process.env.PENALTY_FAILED_OP || "10", 10),
    otpRestorationBonus: parseInt(process.env.BONUS_OTP_RESTORE || "20", 10),
  } as RiskDeductionsConfig,

  // 3. Role-Based Document Policies & Limits
  roleDocumentPolicies: {
    "System Administrator": { maxViewsPerMinute: 30, allowedClassifications: ["Public", "Restricted"] },
    "Tahsildar": { maxViewsPerMinute: 20, allowedClassifications: ["Public", "Restricted", "Confidential"] },
    "Deputy Tahsildar": { maxViewsPerMinute: 15, allowedClassifications: ["Public", "Restricted", "Confidential"] },
    "Revenue Inspector (RI)": { maxViewsPerMinute: 10, allowedClassifications: ["Public", "Restricted"] },
    "VAO / Village Officer": { maxViewsPerMinute: 10, allowedClassifications: ["Public", "Restricted"] },
    "Data Entry Operator": { maxViewsPerMinute: 5, allowedClassifications: ["Public"] },
    "Citizen / Land Owner": { maxViewsPerMinute: 3, allowedClassifications: ["Public"] }
  } as Record<string, RoleDocumentPolicy>,

  // 4. Alert Policies
  alertPolicy: {
    significantDropThreshold: parseInt(process.env.TRUST_SIGNIFICANT_DROP_THRESHOLD || "20", 10),
    cooldownMinutes: parseInt(process.env.ALERT_COOLDOWN_MINUTES || "10", 10),
    alertOnLowRisk: process.env.ALERT_ON_LOW_RISK === "true",
    alertOnMediumRisk: process.env.ALERT_ON_MEDIUM_RISK === "true",
    alertOnHighRisk: process.env.ALERT_ON_HIGH_RISK !== "false",
    alertOnCritical: process.env.ALERT_ON_CRITICAL !== "false",
  } as AlertPolicyConfig,

  // 5. NodeMailer SMTP and Demo Email Destination
  smtp: {
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port: parseInt(process.env.SMTP_PORT || "465", 10),
    secure: process.env.SMTP_SECURE !== "false",
    user: process.env.SMTP_USER || "svkowshiga@gmail.com",
    pass: process.env.SMTP_PASS || "ahbt sffp nmye vfsw",
    from: process.env.SMTP_FROM || '"TrustGuard Security Engine" <svkowshiga@gmail.com>',
    demoOtpEmail: process.env.DEMO_OTP_EMAIL || process.env.OVERRIDE_RECIPIENT_EMAIL || "kowshiga931@gmail.com",
    securityAlertEmail: process.env.SECURITY_ALERT_EMAIL || "kowshiga931@gmail.com",
    enabled: process.env.ENABLE_EMAIL_ALERTS !== "false",
  } as SmtpConfig,

  // 6. Machine Learning Microservice Configuration
  ml: {
    serviceUrl: process.env.ML_SERVICE_URL || "http://127.0.0.1:8000/predict",
    timeoutMs: parseInt(process.env.ML_TIMEOUT_MS || "2000", 10),
    weight: parseFloat(process.env.ML_SCORE_WEIGHT || "0.25"),
  } as MlConfig,

  // 7. Role-Specific Low Trust Challenge Baseline
  roleOtpThresholds: {
    "System Administrator": parseInt(process.env.OTP_THRESHOLD_ADMIN || "60", 10),
    "Tahsildar": parseInt(process.env.OTP_THRESHOLD_TAHSILDAR || "60", 10),
    "Deputy Tahsildar": parseInt(process.env.OTP_THRESHOLD_DEPUTY_TAHSILDAR || "60", 10),
    "Revenue Inspector (RI)": parseInt(process.env.OTP_THRESHOLD_RI || "60", 10),
    "VAO / Village Officer": parseInt(process.env.OTP_THRESHOLD_VAO || "60", 10),
    "Data Entry Operator": parseInt(process.env.OTP_THRESHOLD_DEO || "60", 10),
    "Citizen / Land Owner": parseInt(process.env.OTP_THRESHOLD_CITIZEN || "50", 10),
  } as Record<string, number>
};

/**
 * Determine the Risk Level based on centralized trust score thresholds:
 *   80–100: LOW
 *   60–79:  MEDIUM
 *   40–59:  HIGH
 *   < 40:   CRITICAL
 */
export function getRiskLevel(score: number): RiskLevel {
  const { lowRiskMin, mediumRiskMin, highRiskMin } = trustConfig.thresholds;
  if (score >= lowRiskMin) return RiskLevel.LOW;
  if (score >= mediumRiskMin) return RiskLevel.MEDIUM;
  if (score >= highRiskMin) return RiskLevel.HIGH;
  return RiskLevel.CRITICAL;
}

/**
 * Determine the Access Mode based on centralized policy:
 *   80–100: FULL (OTP not required)
 *   60–79:  RESTRICTED (OTP required for sensitive write actions / approvals)
 *   40–59:  READ-ONLY (sensitive actions blocked, OTP required to restore)
 *   < 40:   BLOCKED (session challenged/terminated)
 */
export function getAccessModeForScore(score: number): AccessMode {
  const risk = getRiskLevel(score);
  switch (risk) {
    case RiskLevel.LOW:
      return AccessMode.FULL;
    case RiskLevel.MEDIUM:
      return AccessMode.RESTRICTED;
    case RiskLevel.HIGH:
      return AccessMode.READ_ONLY;
    case RiskLevel.CRITICAL:
      return AccessMode.BLOCKED;
  }
}

export function getPolicyDecisionForRisk(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case RiskLevel.LOW:
      return "FULL_ACCESS";
    case RiskLevel.MEDIUM:
      return "RESTRICTED";
    case RiskLevel.HIGH:
      return "READ_ONLY";
    case RiskLevel.CRITICAL:
      return "BLOCKED";
    default:
      return "RESTRICTED";
  }
}

/**
 * Check if a risk level is configured to trigger an email alert.
 */
export function isRiskLevelAlertable(riskLevel: RiskLevel): boolean {
  switch (riskLevel) {
    case RiskLevel.LOW:
      return trustConfig.alertPolicy.alertOnLowRisk;
    case RiskLevel.MEDIUM:
      return trustConfig.alertPolicy.alertOnMediumRisk;
    case RiskLevel.HIGH:
      return trustConfig.alertPolicy.alertOnHighRisk;
    case RiskLevel.CRITICAL:
      return trustConfig.alertPolicy.alertOnCritical;
    default:
      return false;
  }
}

/**
 * Returns role-specific document policy (rate limit & allowed classifications).
 */
export function getRoleDocumentPolicy(role: string): RoleDocumentPolicy {
  if (!role) return { maxViewsPerMinute: 10, allowedClassifications: ["Public"] };
  const normalized = role.toLowerCase();

  for (const [rName, policy] of Object.entries(trustConfig.roleDocumentPolicies)) {
    if (normalized.includes(rName.toLowerCase()) || rName.toLowerCase().includes(normalized)) {
      return policy;
    }
  }

  if (normalized.includes("admin")) return trustConfig.roleDocumentPolicies["System Administrator"];
  if (normalized.includes("tahsildar") && !normalized.includes("deputy")) return trustConfig.roleDocumentPolicies["Tahsildar"];
  if (normalized.includes("deputy")) return trustConfig.roleDocumentPolicies["Deputy Tahsildar"];
  if (normalized.includes("inspector") || normalized.includes("ri")) return trustConfig.roleDocumentPolicies["Revenue Inspector (RI)"];
  if (normalized.includes("vao") || normalized.includes("village")) return trustConfig.roleDocumentPolicies["VAO / Village Officer"];
  if (normalized.includes("deo") || normalized.includes("operator")) return trustConfig.roleDocumentPolicies["Data Entry Operator"];
  if (normalized.includes("citizen")) return trustConfig.roleDocumentPolicies["Citizen / Land Owner"];

  return { maxViewsPerMinute: 10, allowedClassifications: ["Public", "Restricted"] };
}

/**
 * Returns the configurable low-trust OTP challenge threshold for a given user role.
 */
export function getRoleOtpThreshold(role: string): number {
  if (!role) return trustConfig.thresholds.mediumRiskMin;
  
  if (trustConfig.roleOtpThresholds[role] !== undefined) {
    return trustConfig.roleOtpThresholds[role];
  }

  const normalized = role.toLowerCase();
  for (const [rName, threshold] of Object.entries(trustConfig.roleOtpThresholds)) {
    const key = rName.toLowerCase();
    if (normalized.includes(key) || key.includes(normalized)) {
      return threshold;
    }
  }

  if (normalized.includes("admin")) return trustConfig.roleOtpThresholds["System Administrator"] || 60;
  if (normalized.includes("deputy") || normalized.includes("dt")) return trustConfig.roleOtpThresholds["Deputy Tahsildar"] || 60;
  if (normalized.includes("tahsildar")) return trustConfig.roleOtpThresholds["Tahsildar"] || 60;
  if (normalized.includes("vao") || normalized.includes("village")) return trustConfig.roleOtpThresholds["VAO / Village Officer"] || 60;
  if (normalized.includes("ri") || normalized.includes("inspector")) return trustConfig.roleOtpThresholds["Revenue Inspector (RI)"] || 60;
  if (normalized.includes("deo") || normalized.includes("data entry")) return trustConfig.roleOtpThresholds["Data Entry Operator"] || 60;
  if (normalized.includes("citizen")) return trustConfig.roleOtpThresholds["Citizen / Land Owner"] || 50;

  return trustConfig.thresholds.mediumRiskMin; // default 60
}
