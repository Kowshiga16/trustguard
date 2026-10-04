/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard: Zero Trust Access Control Configuration
 * Centralized, environment-driven configuration for trust score thresholds,
 * risk levels, alert cooldowns, and SMTP credentials.
 */

export enum RiskLevel {
  NORMAL = "NORMAL",
  LOW_RISK = "LOW RISK",
  SUSPICIOUS = "SUSPICIOUS",
  HIGH_RISK = "HIGH RISK",
  CRITICAL = "CRITICAL"
}

export interface TrustThresholds {
  normalMin: number;      // >= 80: Normal access
  lowRiskMin: number;     // 60 - 79: Low risk, continuous monitoring
  suspiciousMin: number;  // 40 - 59: Suspicious activity, Step-up OTP challenge
  highRiskMin: number;    // 20 - 39: High risk, restricted read-only or re-auth
  criticalMax: number;    // < 20: Critical breach, session terminated
}

export interface AlertPolicyConfig {
  significantDropThreshold: number; // Minimum score drop to trigger alert (default: 20)
  cooldownMinutes: number;          // Deduplication cooldown window (default: 10 mins)
  alertOnLowRisk: boolean;          // Default false
  alertOnSuspicious: boolean;       // Default true
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
  securityAlertEmail: string;
  enabled: boolean;
}

export interface MlConfig {
  serviceUrl: string;
  timeoutMs: number;
  weight: number; // ML weight in final trust score (0.0 to 1.0, default 0.25)
}

export const trustConfig = {
  thresholds: {
    normalMin: parseInt(process.env.TRUST_THRESHOLD_NORMAL_MIN || "76", 10),       // 76-100: FULL_ACCESS
    lowRiskMin: parseInt(process.env.TRUST_THRESHOLD_LOW_RISK_MIN || "61", 10),      // 61-75: READ_ONLY
    suspiciousMin: parseInt(process.env.TRUST_THRESHOLD_SUSPICIOUS_MIN || "51", 10), // 51-60: OTP_REQUIRED
    highRiskMin: parseInt(process.env.TRUST_THRESHOLD_HIGH_RISK_MIN || "0", 10),     // Unused in new scale, can keep as fallback
    criticalMax: parseInt(process.env.TRUST_THRESHOLD_CRITICAL_MAX || "51", 10),     // <51 (0-50): TERMINATE_SESSION
  } as TrustThresholds,

  alertPolicy: {
    significantDropThreshold: parseInt(process.env.TRUST_SIGNIFICANT_DROP_THRESHOLD || "20", 10),
    cooldownMinutes: parseInt(process.env.ALERT_COOLDOWN_MINUTES || "10", 10),
    alertOnLowRisk: process.env.ALERT_ON_LOW_RISK === "true",
    alertOnSuspicious: process.env.ALERT_ON_SUSPICIOUS !== "false", // default true
    alertOnHighRisk: process.env.ALERT_ON_HIGH_RISK !== "false",     // default true
    alertOnCritical: process.env.ALERT_ON_CRITICAL !== "false",       // default true
  } as AlertPolicyConfig,

  smtp: {
    host: process.env.SMTP_HOST || "",
    port: parseInt(process.env.SMTP_PORT || "587", 10),
    secure: process.env.SMTP_SECURE === "true",
    user: process.env.SMTP_USER || "",
    pass: process.env.SMTP_PASS || "",
    from: process.env.SMTP_FROM || '"TrustGuard Security Engine" <security-alerts@trustguard.gov.in>',
    securityAlertEmail: process.env.SECURITY_ALERT_EMAIL || "security-admin@trustguard.gov.in",
    enabled: process.env.ENABLE_EMAIL_ALERTS !== "false",
  } as SmtpConfig,

  ml: {
    serviceUrl: process.env.ML_SERVICE_URL || "http://127.0.0.1:8000/predict",
    timeoutMs: parseInt(process.env.ML_TIMEOUT_MS || "1500", 10),
    weight: parseFloat(process.env.ML_SCORE_WEIGHT || "0.25"),
  } as MlConfig,

  roleOtpThresholds: {
    "System Administrator": parseInt(process.env.OTP_THRESHOLD_ADMIN || "70", 10),
    "Tahsildar": parseInt(process.env.OTP_THRESHOLD_TAHSILDAR || "70", 10),
    "Deputy Tahsildar": parseInt(process.env.OTP_THRESHOLD_DEPUTY_TAHSILDAR || "65", 10),
    "Revenue Inspector (RI)": parseInt(process.env.OTP_THRESHOLD_RI || "60", 10),
    "VAO / Village Officer": parseInt(process.env.OTP_THRESHOLD_VAO || "60", 10),
    "Data Entry Operator": parseInt(process.env.OTP_THRESHOLD_DEO || "60", 10),
    "Citizen / Land Owner": parseInt(process.env.OTP_THRESHOLD_CITIZEN || "50", 10),
  } as Record<string, number>
};

/**
 * Determine the Risk Level based on configurable trust score thresholds.
 */
export function getRiskLevel(score: number): RiskLevel {
  const { normalMin, lowRiskMin, suspiciousMin, highRiskMin } = trustConfig.thresholds;
  if (score >= normalMin) return RiskLevel.NORMAL;
  if (score >= lowRiskMin) return RiskLevel.LOW_RISK;
  if (score >= suspiciousMin) return RiskLevel.SUSPICIOUS;
  if (score >= highRiskMin) return RiskLevel.HIGH_RISK;
  return RiskLevel.CRITICAL;
}

export function getPolicyDecisionForRisk(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case RiskLevel.NORMAL:
      return "FULL_ACCESS";
    case RiskLevel.LOW_RISK:
      return "READ_ONLY";
    case RiskLevel.SUSPICIOUS:
      return "OTP_REQUIRED";
    case RiskLevel.HIGH_RISK:
    case RiskLevel.CRITICAL:
      return "TERMINATE_SESSION";
    default:
      return "OTP_REQUIRED";
  }
}

/**
 * Check if a risk level is configured to trigger an email alert.
 */
export function isRiskLevelAlertable(riskLevel: RiskLevel): boolean {
  switch (riskLevel) {
    case RiskLevel.NORMAL:
      return false;
    case RiskLevel.LOW_RISK:
      return trustConfig.alertPolicy.alertOnLowRisk;
    case RiskLevel.SUSPICIOUS:
      return trustConfig.alertPolicy.alertOnSuspicious;
    case RiskLevel.HIGH_RISK:
      return trustConfig.alertPolicy.alertOnHighRisk;
    case RiskLevel.CRITICAL:
      return trustConfig.alertPolicy.alertOnCritical;
    default:
      return false;
  }
}

/**
 * Returns the configurable low-trust OTP challenge threshold for a given user role.
 * Executive roles like Tahsildar / System Administrator require higher baseline trust (e.g. 70),
 * while Citizen portal users have a more lenient threshold (e.g. 50).
 */
export function getRoleOtpThreshold(role: string): number {
  if (!role) return trustConfig.thresholds.lowRiskMin;
  
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

  // Common aliases
  if (normalized.includes("admin")) return trustConfig.roleOtpThresholds["System Administrator"] || 70;
  if (normalized.includes("deputy") || normalized.includes("dt")) return trustConfig.roleOtpThresholds["Deputy Tahsildar"] || 65;
  if (normalized.includes("tahsildar") || normalized.includes("tehsildar")) return trustConfig.roleOtpThresholds["Tahsildar"] || 70;
  if (normalized.includes("vao") || normalized.includes("village")) return trustConfig.roleOtpThresholds["VAO / Village Officer"] || 60;
  if (normalized.includes("ri") || normalized.includes("inspector")) return trustConfig.roleOtpThresholds["Revenue Inspector (RI)"] || 60;
  if (normalized.includes("deo") || normalized.includes("data entry")) return trustConfig.roleOtpThresholds["Data Entry Operator"] || 60;
  if (normalized.includes("citizen")) return trustConfig.roleOtpThresholds["Citizen / Land Owner"] || 50;

  return trustConfig.thresholds.lowRiskMin; // default 60
}

