/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Dynamic Trust Engine & Policy Decision Point
 * Orchestrates:
 *  1. Rule-Based Contextual Trust Scoring
 *  2. Scikit-Learn Isolation Forest ML Anomaly Scoring
 *  3. Combined Final Trust Calculation
 *  4. Continuous Evaluation & Alert Triggering
 *  5. Asynchronous NodeMailer Security Email Dispatch
 */

import { ActiveSession, AuditLog, TrustLog, SecurityAlert, User } from "../src/types";
import { trustConfig, RiskLevel, getRiskLevel, getPolicyDecisionForRisk } from "./trustConfig";
import { mlService, MLPredictionResult } from "./mlService";
import { alertManager, AlertEvaluationResult } from "./alertManager";

import { hybridTrustService, HybridTrustScoreResult } from "./hybridTrustService";

export interface TrustEngineEvaluation {
  previousScore: number;
  finalScore: number;
  ruleBasedScore: number;
  hybridResult: HybridTrustScoreResult;
  riskLevel: RiskLevel;
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
   * Calculates the rule-based trust score component from multi-signal context.
   */
  public calculateRuleBasedScore(session: ActiveSession): number {
    let score = 75; // Baseline trust

    // Organic 10 AM to 4 PM working hours check
    const currentHour = new Date().getHours();
    if ((currentHour < 10 || currentHour >= 16) && !session.otpVerified) {
      session.simulatedNightAccess = true;
    }

    if (session.simulatedDeviceMismatch) {
      score -= 25; // Critical device mismatch
    }
    if (session.simulatedIpMismatch) {
      score -= 20; // High risk IP change
    }
    if (session.simulatedNightAccess) {
      score -= 10; // Off-hours penalty
    }
    if (session.simulatedOutsideJurisdiction) {
      score -= 20; // Accessing records outside jurisdiction
    }
    if (session.simulatedSpamTriggered) {
      score -= 15; // Spam detection
    }
    if (session.simulatedIdleTriggered) {
      score -= 10; // Idle burst threat
    }
    if (session.failedActionCount > 0) {
      score -= (session.failedActionCount * 12); // Exponential failed actions penalty
    }

    // Positive trust signals
    if (session.otpVerified) {
      score += 15;
    }
    if (!session.simulatedDeviceMismatch && !session.simulatedIpMismatch) {
      score += 10; // Stable context bonus
    }

    return Math.min(100, Math.max(0, score));
  }

  /**
   * Combines rule-based score and ML Isolation Forest anomaly score into final trust score.
   */
  public calculateFinalTrustScore(ruleScore: number, mlResult: MLPredictionResult): number {
    // If ML detects an anomaly, subtract risk penalty (0-25)
    let score = ruleScore;
    if (mlResult.isAnomaly && mlResult.riskPenalty > 0) {
      score -= mlResult.riskPenalty;
    }
    return Math.min(100, Math.max(0, Math.round(score)));
  }

  /**
   * Full dynamic trust evaluation pipeline:
   * Request -> Rule Score -> ML Anomaly Score -> Final Trust Score ->
   * Risk Level -> Alert Evaluation -> NodeMailer Email -> Audit Trail.
   */
  public async evaluateSessionTrust(
    session: ActiveSession,
    eventType: string = "Continuous Evaluation",
    user?: User,
    reqResource: string = "/api/continuous-eval"
  ): Promise<TrustEngineEvaluation> {
    const previousScore = session.currentTrustScore;

    // If session is already blocked and unverified, preserve blocked status
    if (session.status === "Blocked" && !session.otpVerified) {
      session.currentTrustScore = Math.min(session.currentTrustScore, 40);
      return {
        previousScore,
        finalScore: session.currentTrustScore,
        ruleBasedScore: session.currentTrustScore,
        hybridResult: {
          ruleRisk: 60,
          ruleTrust: session.currentTrustScore,
          isolationForestScore: 0.0,
          normalizedAnomalyScore: 1.0,
          mlRisk: 25.0,
          finalTrustScore: session.currentTrustScore,
          isAnomaly: true,
          mlServiceStatus: "AVAILABLE"
        },
        riskLevel: RiskLevel.Critical,
        policyDecision: "TERMINATE_SESSION",
        reasons: ["Session locked due to critical security degradation"],
        alertTriggered: false,
        alertSuppressedByCooldown: true
      };
    }

    // 1-3. Call Hybrid Trust Service (reusing existing rule calculation + scikit-learn ML)
    const hybridResult = await hybridTrustService.calculateHybridTrust(session);
    const finalScore = hybridResult.finalTrustScore;
    const ruleScore = hybridResult.ruleTrust;

    // 4. Update session state
    session.currentTrustScore = finalScore;
    session.lastActivityTime = new Date().toISOString();

    // Enforce session status based on configurable thresholds
    if (finalScore <= 50) { // Phase 14 rule: 0-50 -> TERMINATE_SESSION
      session.status = "Blocked";
    } else if (session.status === "Blocked" && finalScore > 50) {
      session.status = "Active";
    }

    const currentRisk = getRiskLevel(finalScore);
    const policyDecision = getPolicyDecisionForRisk(currentRisk);

    // 5. Evaluate Alert Thresholds & Cooldowns
    const alertEval: AlertEvaluationResult = alertManager.evaluateAlert(
      session,
      previousScore,
      finalScore,
      user,
      reqResource,
      hybridResult.isolationForestScore, // Use the real scikit-learn decision function score
      eventType
    );

    // 6. If alert qualified, dispatch email via NodeMailer asynchronously
    if (alertEval.shouldAlert && alertEval.securityAlert) {
      // Non-blocking dispatch
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
      policyDecision,
      reasons: alertEval.reasons,
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
