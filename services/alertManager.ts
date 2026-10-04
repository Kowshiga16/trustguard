/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Alert Manager & Deduplication Engine
 * Evaluates risk transitions, enforces configurable cooldowns to prevent email spam,
 * extracts forensic reasons, and dispatches security notifications via NodeMailer.
 */

import { trustConfig, RiskLevel, getRiskLevel, getPolicyDecisionForRisk, isRiskLevelAlertable } from "./trustConfig";
import { emailService, TrustAlertEmailData, EmailSendResult } from "./emailService";
import { ActiveSession, SecurityAlert, AuditLog, RoleName, User } from "../src/types";

interface CooldownEntry {
  lastAlertTime: number;
  lastRiskLevel: RiskLevel;
  lastTrustScore: number;
  lastReasonsKey: string;
}

export interface AlertEvaluationResult {
  shouldAlert: boolean;
  isSuppressedByCooldown: boolean;
  triggerReason: string;
  riskLevel: RiskLevel;
  policyDecision: string;
  reasons: string[];
  securityAlert?: SecurityAlert;
  auditEntry?: AuditLog;
}

class AlertManager {
  // In-memory cooldown cache keyed by userId
  private cooldownCache: Map<string, CooldownEntry> = new Map();
  // Persistent or in-memory list of alerts
  private alertsLog: SecurityAlert[] = [];

  /**
   * Resets the cooldown cache (useful for testing and admin resets).
   */
  public clearCooldown(userId?: string): void {
    if (userId) {
      this.cooldownCache.delete(userId);
    } else {
      this.cooldownCache.clear();
    }
  }

  /**
   * Retrieves security alerts for audit and forensic dashboards.
   */
  public getAlerts(): SecurityAlert[] {
    return [...this.alertsLog];
  }

  /**
   * Stores an alert in memory.
   */
  public recordAlert(alert: SecurityAlert): void {
    if (!alert.status) alert.status = "NEW";
    this.alertsLog.unshift(alert);
    // Keep bounded history
    if (this.alertsLog.length > 500) {
      this.alertsLog.pop();
    }
  }

  public updateAlertStatus(alertId: string, status: "NEW" | "INVESTIGATING" | "RESOLVED", adminUser: string, notes?: string): boolean {
    const alert = this.alertsLog.find(a => a.id === alertId);
    if (!alert) return false;
    alert.status = status;
    alert.investigatedBy = adminUser;
    if (notes) alert.resolutionNotes = notes;
    return true;
  }

  /**
   * Identifies all forensic reasons contributing to a trust score drop.
   */
  public extractReasons(session: ActiveSession, mlScore?: number, customReason?: string): string[] {
    const reasons: string[] = [];

    if (customReason && !customReason.includes("Continuous Evaluation")) {
      reasons.push(customReason);
    }

    if (session.simulatedDeviceMismatch) {
      reasons.push("Unrecognized device fingerprint detected (untrusted hardware/browser)");
    }
    if (session.simulatedIpMismatch) {
      reasons.push(`Unusual IP address / mid-session network route shift (${session.ipAddress})`);
    }
    if (session.simulatedOutsideJurisdiction) {
      reasons.push("Cross-jurisdiction land records access attempt outside assigned administrative zone");
    }
    if (session.simulatedNightAccess) {
      reasons.push("Off-hours session activity detected outside normal government working hours");
    }
    if (session.simulatedSpamTriggered) {
      reasons.push("Abnormal request velocity / rapid API spike (>25 requests/min)");
    }
    if (session.simulatedIdleTriggered) {
      reasons.push("Post-idle burst activity threat pattern detected");
    }
    if (session.failedActionCount > 0) {
      reasons.push(`Repeated unauthorized/failed security actions (${session.failedActionCount} failure[s])`);
    }
    if (typeof mlScore === "number" && mlScore >= 0.40) {
      reasons.push(`ML Isolation Forest detected anomalous behavioral pattern (Risk Score: ${(mlScore * 100).toFixed(0)}%)`);
    }

    if (reasons.length === 0) {
      reasons.push("Dynamic Trust Engine detected statistical anomaly during continuous policy evaluation");
    }

    return reasons;
  }

  /**
   * Evaluates whether a trust score change qualifies for an email notification.
   * Enforces configurable risk thresholds, significant drops, and deduplication cooldowns.
   */
  public evaluateAlert(
    session: ActiveSession,
    previousScore: number,
    currentScore: number,
    user?: User,
    resourceAccessed: string = "DYNAMIC_TRUST_ENGINE",
    mlScore?: number,
    customEvent?: string
  ): AlertEvaluationResult {
    const scoreDiff = currentScore - previousScore;
    const currentRisk = getRiskLevel(currentScore);
    const prevRisk = getRiskLevel(previousScore);
    const policyDecision = getPolicyDecisionForRisk(currentRisk);
    const reasons = this.extractReasons(session, mlScore, customEvent);

    // If score did not decrease, no alert needed
    if (scoreDiff >= 0) {
      return {
        shouldAlert: false,
        isSuppressedByCooldown: false,
        triggerReason: "No score reduction",
        riskLevel: currentRisk,
        policyDecision,
        reasons
      };
    }

    // Determine if trigger criteria are met:
    // 1. Risk level crossed into an alertable level (e.g. NORMAL/LOW -> SUSPICIOUS, HIGH RISK, or CRITICAL)
    const crossedIntoAlertableTier = isRiskLevelAlertable(currentRisk) && currentRisk !== prevRisk;

    // 2. Escalated to a worse risk level (e.g. SUSPICIOUS -> HIGH_RISK or HIGH_RISK -> CRITICAL)
    const escalatedWorseRisk = this.getRiskSeverity(currentRisk) > this.getRiskSeverity(prevRisk);

    // 3. Significant trust-score drop (>= threshold, default 20)
    const absoluteDrop = Math.abs(scoreDiff);
    const isSignificantDrop = absoluteDrop >= trustConfig.alertPolicy.significantDropThreshold && isRiskLevelAlertable(currentRisk);

    // 4. Critical security event (e.g. score < 20, or both device & IP mismatch, or blocked status)
    const isCriticalEvent = currentScore < trustConfig.thresholds.criticalMax || 
      (session.simulatedDeviceMismatch && session.simulatedIpMismatch);

    const qualifiesForAlert = crossedIntoAlertableTier || escalatedWorseRisk || isSignificantDrop || isCriticalEvent;

    if (!qualifiesForAlert) {
      return {
        shouldAlert: false,
        isSuppressedByCooldown: false,
        triggerReason: `Score drop of ${scoreDiff} does not cross alertable threshold (Risk: ${currentRisk})`,
        riskLevel: currentRisk,
        policyDecision,
        reasons
      };
    }

    // Cooldown & Deduplication Verification
    const now = Date.now();
    const cooldownMs = trustConfig.alertPolicy.cooldownMinutes * 60 * 1000;
    const cooldownKey = session.userId || session.id;
    const lastAlert = this.cooldownCache.get(cooldownKey);

    const reasonsKey = reasons.sort().join("|");

    if (lastAlert) {
      const timeSinceLastAlert = now - lastAlert.lastAlertTime;
      const isWithinCooldown = timeSinceLastAlert < cooldownMs;

      // If within cooldown window:
      if (isWithinCooldown) {
        // Allow alert only if risk escalated to a more severe tier (e.g. SUSPICIOUS -> HIGH RISK or -> CRITICAL)
        // or a massive subsequent drop occurred (> significantDropThreshold from last alerted score)
        const furtherDropSinceLastAlert = lastAlert.lastTrustScore - currentScore;
        const escalatedFurther = this.getRiskSeverity(currentRisk) > this.getRiskSeverity(lastAlert.lastRiskLevel);
        const significantNewDrop = furtherDropSinceLastAlert >= trustConfig.alertPolicy.significantDropThreshold;

        if (!escalatedFurther && !significantNewDrop && currentRisk !== RiskLevel.CRITICAL) {
          console.log(
            `[AlertManager] Alert suppressed by cooldown/deduplication for ${session.userName}. ` +
            `(Risk: ${currentRisk} unchanged, Score ${previousScore}->${currentScore}, Cooldown remaining: ${Math.round((cooldownMs - timeSinceLastAlert) / 1000)}s)`
          );

          return {
            shouldAlert: false,
            isSuppressedByCooldown: true,
            triggerReason: `Suppressed by cooldown (${Math.round(timeSinceLastAlert / 1000)}s ago)`,
            riskLevel: currentRisk,
            policyDecision,
            reasons
          };
        }
      }
    }

    // Trigger reason description
    let triggerReason = "Risk threshold crossed into alertable level";
    if (isCriticalEvent) triggerReason = "Critical security anomaly detected (Trust Score < 20 or High-Risk Combination)";
    else if (escalatedWorseRisk) triggerReason = `Risk level escalated from ${prevRisk} to ${currentRisk}`;
    else if (isSignificantDrop) triggerReason = `Significant trust score drop (-${absoluteDrop} points)`;

    // Update cooldown cache
    this.cooldownCache.set(cooldownKey, {
      lastAlertTime: now,
      lastRiskLevel: currentRisk,
      lastTrustScore: currentScore,
      lastReasonsKey: reasonsKey
    });

    // Resolve location
    const location = this.resolveLocation(session, user);

    // Prepare Security Alert Record
    const alertId = `alt_${now}_${Math.random().toString(36).substr(2, 6)}`;
    const securityAlert: SecurityAlert = {
      id: alertId,
      userId: session.userId,
      userName: session.userName,
      userEmail: session.userEmail || user?.email || "unknown@revenue.tn.gov.in",
      userRole: session.role,
      previousTrustScore: previousScore,
      currentTrustScore: currentScore,
      riskLevel: currentRisk,
      reasons,
      ipAddress: session.ipAddress,
      location,
      deviceFingerprint: session.deviceFingerprint,
      policyAction: policyDecision,
      timestamp: new Date(now).toISOString(),
      emailAlertSent: false,
      emailRecipient: trustConfig.smtp.securityAlertEmail,
      emailStatus: "SENT",
      requestResource: resourceAccessed
    };

    // Prepare Comprehensive Audit Log
    const auditEntry: AuditLog = {
      id: `al_alert_${now}_${Math.random().toString(36).substr(2, 5)}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role as RoleName,
      actionPerformed: `SECURITY_ALERT_TRIGGERED: ${currentRisk} (${triggerReason})`,
      resourceAccessed,
      trustScoreAtAction: currentScore,
      decision: currentScore < 20 ? "TERMINATED" : (currentScore < 60 ? "STEP-UP OTP" : "LIMITED ACCESS"),
      timestamp: new Date(now).toISOString(),
      previousTrustScore: previousScore,
      currentTrustScore: currentScore,
      riskLevel: currentRisk,
      reasons,
      ipAddress: session.ipAddress,
      location,
      device: session.deviceFingerprint,
      emailAlertSent: true,
      emailAlertDetails: {
        alertId,
        recipient: trustConfig.smtp.securityAlertEmail,
        subject: `TrustGuard Security Alert: Suspicious Activity Detected [${currentRisk}]`,
        status: "SENT",
        sentAt: new Date(now).toISOString()
      },
      policyAction: policyDecision
    };

    return {
      shouldAlert: true,
      isSuppressedByCooldown: false,
      triggerReason,
      riskLevel: currentRisk,
      policyDecision,
      reasons,
      securityAlert,
      auditEntry
    };
  }

  /**
   * Dispatches the email notification asynchronously without blocking API responses.
   */
  public async dispatchAlertEmail(
    alert: SecurityAlert, 
    onResult?: (result: EmailSendResult) => void
  ): Promise<EmailSendResult> {
    const emailData: TrustAlertEmailData = {
      userName: alert.userName,
      userEmail: alert.userEmail,
      userRole: alert.userRole,
      previousTrustScore: alert.previousTrustScore,
      currentTrustScore: alert.currentTrustScore,
      riskLevel: alert.riskLevel,
      reasons: alert.reasons,
      ipAddress: alert.ipAddress,
      location: alert.location,
      device: alert.deviceFingerprint,
      timestamp: alert.timestamp,
      policyDecision: alert.policyAction,
      requestResource: alert.requestResource,
      recipientEmail: alert.emailRecipient
    };

    const result = await emailService.sendTrustScoreAlert(emailData);

    alert.emailAlertSent = result.success;
    alert.emailStatus = result.success ? (result.simulated ? "SIMULATED_LOGGED" : "SENT") : "FAILED";
    if (result.error) alert.emailError = result.error;

    this.recordAlert(alert);

    if (onResult) onResult(result);
    return result;
  }

  /**
   * Helper to map risk levels to numerical severity for comparison.
   */
  private getRiskSeverity(level: RiskLevel): number {
    switch (level) {
      case RiskLevel.NORMAL: return 0;
      case RiskLevel.LOW_RISK: return 1;
      case RiskLevel.SUSPICIOUS: return 2;
      case RiskLevel.HIGH_RISK: return 3;
      case RiskLevel.CRITICAL: return 4;
      default: return 0;
    }
  }

  /**
   * Resolves realistic location from user profile and network context.
   */
  public resolveLocation(session: ActiveSession, user?: User): string {
    if (session.simulatedOutsideJurisdiction) {
      return "Outside Assigned Jurisdiction (Remote IP)";
    }
    if (session.simulatedIpMismatch) {
      return "External Network / Dynamic VPN Proxy";
    }
    if (user?.assignedJurisdiction) {
      const parts = [];
      if (user.assignedJurisdiction.villageId) parts.push(`Village ${user.assignedJurisdiction.villageId}`);
      if (user.assignedJurisdiction.taluk) parts.push(user.assignedJurisdiction.taluk);
      if (user.assignedJurisdiction.district) parts.push(user.assignedJurisdiction.district);
      if (parts.length > 0) return `${parts.join(", ")} (Official Office)`;
    }
    return "Local Subnet (192.168.1.0/24 - Government Intranet)";
  }
}

export const alertManager = new AlertManager();
export default alertManager;
