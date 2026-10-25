/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Dynamic Trust Engine & Policy Decision Point
 * Orchestrates:
 *  1. Rule-Based Contextual Trust Scoring (Device, IP, Jurisdiction, Rate Limit)
 *  2. Scikit-Learn Isolation Forest ML Anomaly Scoring
 *  3. Explainable Combined Final Trust Calculation (Starts at 100)
 *  4. Continuous Evaluation & Alert Triggering
 *  5. Asynchronous NodeMailer Security Email Dispatch
 */

import { ActiveSession, AuditLog, TrustLog, SecurityAlert, User } from "../src/types";
import { trustConfig, RiskLevel, AccessMode, getRiskLevel, getAccessModeForScore, getPolicyDecisionForRisk } from "./trustConfig";
import { alertManager, AlertEvaluationResult } from "./alertManager";
import { hybridTrustService, HybridTrustScoreResult } from "./hybridTrustService";
import { sessionActivityTracker } from "./sessionActivityTracker";

export interface RuleDeductionResult {
  totalDeductions: number;
  factorBreakdown: Record<string, number>;
}

export interface TrustEngineEvaluation {
  previousScore: number;
  finalScore: number;
  ruleBasedScore: number;
  hybridResult: HybridTrustScoreResult;
  riskLevel: RiskLevel;
  accessMode: AccessMode;
  policyDecision: string;
  reasons: string[];
  alertTriggered: boolean;
  alertSuppressedByCooldown: boolean;
  securityAlert?: SecurityAlert;
  auditEntry?: AuditLog;
  trustLog?: TrustLog;
}

class TrustEngine {
  /**
   * Evaluates explainable rule-based deductions.
   * Starts from a baseline of 100; deductions applied only upon threat evidence.
   */
  public evaluateRuleDeductions(session: ActiveSession): RuleDeductionResult {
    let totalDeductions = 0;
    const factorBreakdown: Record<string, number> = {};

    const { deductions } = trustConfig;

    if (session.simulatedDeviceMismatch) {
      totalDeductions += deductions.newDevice;
      factorBreakdown["New Device / Fingerprint Mismatch"] = deductions.newDevice;
    }

    if (session.simulatedIpMismatch) {
      totalDeductions += deductions.differentIp;
      factorBreakdown["Different IP / Network Route Drift"] = deductions.differentIp;
    }

    let currentHour = new Date().getHours();
    try {
      const istStr = new Intl.DateTimeFormat('en-US', {
        timeZone: 'Asia/Kolkata',
        hour: 'numeric',
        hour12: false
      }).format(new Date());
      currentHour = parseInt(istStr, 10);
    } catch {
      currentHour = new Date().getHours();
    }
    const isRealClockEnforced = process.env.NODE_ENV !== "test";
    const isRealOffHours = isRealClockEnforced && (currentHour < 7 || currentHour >= 19);
    if (session.simulatedNightAccess || isRealOffHours) {
      totalDeductions += deductions.offHoursAccess;
      factorBreakdown["Off-Hours Registry Access"] = deductions.offHoursAccess;
    }

    if (session.simulatedOutsideJurisdiction) {
      totalDeductions += deductions.outsideJurisdiction;
      factorBreakdown["Cross-Jurisdiction Access Attempt"] = deductions.outsideJurisdiction;
    }

    const rateExceeded = session.simulatedSpamTriggered || sessionActivityTracker.isRateLimitExceeded(session.id);
    if (rateExceeded) {
      totalDeductions += deductions.rateLimitViolation;
      factorBreakdown["Document Request Velocity Violation"] = deductions.rateLimitViolation;
    }

    if (session.simulatedIdleTriggered) {
      totalDeductions += 10;
      factorBreakdown["Post-Idle Burst Anomaly"] = 10;
    }

    if (session.failedActionCount && session.failedActionCount > 0) {
      const failDeduction = session.failedActionCount * deductions.failedOperation;
      totalDeductions += failDeduction;
      factorBreakdown[`Unauthorized / Failed Attempts (${session.failedActionCount})`] = failDeduction;
    }

    return { totalDeductions, factorBreakdown };
  }

  /**
   * Calculates the rule-based trust score component: starts at 100, drops on threat signals.
   */
  public calculateRuleBasedScore(session: ActiveSession): number {
    const { totalDeductions } = this.evaluateRuleDeductions(session);
    return Math.max(0, Math.min(100, 100 - totalDeductions));
  }

  /**
   * Full dynamic trust evaluation pipeline:
   * Request -> Rule Score -> Isolation Forest Anomaly -> Final Trust Score ->
   * Risk Level -> Access Mode -> Alert Evaluation -> NodeMailer Email -> Audit Trail.
   */
  public async evaluateSessionTrust(
    session: ActiveSession,
    eventType: string = "Continuous Evaluation",
    user?: User,
    reqResource: string = "/api/continuous-eval"
  ): Promise<TrustEngineEvaluation> {
    const previousScore = session.currentTrustScore ?? 100;

    // If session is already critically blocked and unverified, preserve blocked state
    if (session.status === "Blocked" && !session.otpVerified && previousScore < trustConfig.thresholds.criticalMax) {
      session.currentTrustScore = Math.min(session.currentTrustScore, 35);
      return {
        previousScore,
        finalScore: session.currentTrustScore,
        ruleBasedScore: session.currentTrustScore,
        hybridResult: {
          ruleRisk: 65,
          ruleTrust: session.currentTrustScore,
          isolationForestScore: -0.05,
          normalizedAnomalyScore: 1.0,
          mlRisk: 25.0,
          finalTrustScore: session.currentTrustScore,
          isAnomaly: true,
          mlServiceStatus: "AVAILABLE",
          anomalyReasons: ["Session locked due to critical security degradation"]
        },
        riskLevel: RiskLevel.CRITICAL,
        accessMode: AccessMode.BLOCKED,
        policyDecision: "BLOCKED",
        reasons: ["Session locked due to critical security degradation"],
        alertTriggered: false,
        alertSuppressedByCooldown: true
      };
    }

    // 1-3. Call Hybrid Trust Service (reusing explainable rules + scikit-learn ML)
    const hybridResult = await hybridTrustService.calculateHybridTrust(session);
    const finalScore = hybridResult.finalTrustScore;
    const ruleScore = hybridResult.ruleTrust;

    // 4. Update session state
    session.currentTrustScore = finalScore;
    session.lastActivityTime = new Date().toISOString();

    // Enforce session status based on centralized thresholds
    if (finalScore < trustConfig.thresholds.criticalMax) { // < 40: Critical Risk / Blocked
      session.status = "Blocked";
    } else if (session.status === "Blocked" && finalScore >= trustConfig.thresholds.criticalMax) {
      session.status = "Active";
    }

    const currentRisk = getRiskLevel(finalScore);
    const accessMode = getAccessModeForScore(finalScore);
    const policyDecision = getPolicyDecisionForRisk(currentRisk);

    // Collect explainable reasons for security audit
    const activeReasons: string[] = [];
    if (hybridResult.riskFactors) {
      for (const [factor, pts] of Object.entries(hybridResult.riskFactors)) {
        activeReasons.push(`${factor}: -${pts} pts`);
      }
    }
    if (hybridResult.anomalyReasons && hybridResult.anomalyReasons.length > 0) {
      activeReasons.push(...hybridResult.anomalyReasons);
    }
    if (activeReasons.length === 0) {
      activeReasons.push("Session verified within normal zero trust parameters");
    }

    // 5. Evaluate Alert Thresholds & Cooldowns
    const alertEval: AlertEvaluationResult = alertManager.evaluateAlert(
      session,
      previousScore,
      finalScore,
      user,
      reqResource,
      hybridResult.isolationForestScore,
      eventType
    );

    // 6. If alert qualified, dispatch email via NodeMailer asynchronously
    if (alertEval.shouldAlert && alertEval.securityAlert) {
      alertManager.dispatchAlertEmail(alertEval.securityAlert, (result) => {
        if (alertEval.auditEntry && alertEval.auditEntry.emailAlertDetails) {
          alertEval.auditEntry.emailAlertDetails.status = result.success 
            ? (result.simulated ? "SIMULATED_LOGGED" : "SENT") 
            : "FAILED";
          if (result.error) alertEval.auditEntry.emailAlertDetails.error = result.error;
        }
      }).catch(err => {
        console.error("[TrustEngine] Non-blocking alert email failed:", err);
      });
    }

    // 7. Generate Trust Log if score changed
    let trustLog: TrustLog | undefined;
    const scoreDiff = finalScore - previousScore;
    if (scoreDiff !== 0) {
      trustLog = {
        id: `tl_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
        sessionId: session.id,
        eventType,
        trustChangeValue: scoreDiff,
        resultingTrustScore: finalScore,
        timestamp: new Date().toISOString()
      };
    }

    return {
      previousScore,
      finalScore,
      ruleBasedScore: ruleScore,
      hybridResult,
      riskLevel: currentRisk,
      accessMode,
      policyDecision,
      reasons: activeReasons,
      alertTriggered: alertEval.shouldAlert,
      alertSuppressedByCooldown: alertEval.isSuppressedByCooldown,
      securityAlert: alertEval.securityAlert,
      auditEntry: alertEval.auditEntry,
      trustLog
    };
  }
}

export const trustEngine = new TrustEngine();
export default trustEngine;
