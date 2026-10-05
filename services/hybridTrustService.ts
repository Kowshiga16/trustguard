/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Hybrid Trust Service
 * Combines:
 *  1. Rule-Based Contextual Signals (IP, Device, Jurisdiction, Rate Limit)
 *  2. Scikit-Learn Isolation Forest ML Anomaly Detection Service
 * 
 * Trust Score begins at 100 and only drops with evidence of suspicious activity:
 * FinalTrustScore = max(0, min(100, 100 - RuleRisk - MLRisk + OTPBonus))
 */

import { ActiveSession } from "../src/types";
import { trustEngine } from "./trustEngine";
import { sessionActivityTracker, SessionBehavioralFeatures } from "./sessionActivityTracker";
import { mlService } from "./mlService";

export interface HybridTrustScoreResult {
  ruleRisk: number;
  ruleTrust: number;
  isolationForestScore: number;
  normalizedAnomalyScore: number;
  mlRisk: number;
  finalTrustScore: number;
  isAnomaly: boolean;
  mlServiceStatus: "AVAILABLE" | "LOCAL_ENGINE";
  featuresUsed?: SessionBehavioralFeatures;
  anomalyReasons?: string[];
  riskFactors?: Record<string, number>;
}

class HybridTrustService {
  /**
   * Evaluates the explainable hybrid trust score:
   * Rule-Based Risk + Isolation Forest ML Anomaly Risk
   */
  public async calculateHybridTrust(session: ActiveSession): Promise<HybridTrustScoreResult> {
    // 1. Calculate Rule-Based Risk and deductions
    const ruleEvaluation = trustEngine.evaluateRuleDeductions(session);
    const ruleRisk = ruleEvaluation.totalDeductions;
    const ruleTrust = Math.max(0, 100 - ruleRisk);

    // 2. Query ML Anomaly Detection Service (FastAPI Isolation Forest or trained local engine)
    const mlResult = await mlService.getAnomalyScore(session);
    const mlRisk = mlResult.riskPenalty;
    const isAnomaly = mlResult.isAnomaly;
    const nas = mlResult.anomalyScore;
    const ifs = mlResult.isolationForestScore ?? (0.1604 - nas * 0.1604);
    const mlServiceStatus = mlResult.source === "fastapi" ? "AVAILABLE" : "LOCAL_ENGINE";

    // 3. OTP verification restoration bonus (if verified and not in critical state)
    const restorationBonus = session.otpVerified ? 20 : 0;

    // 4. Final Trust Score: starts at 100, deductions applied
    let calculated = 100 - ruleRisk - mlRisk + restorationBonus;
    const finalTrustScore = Math.max(0, Math.min(100, Math.round(calculated)));

    const riskFactors = {
      ...ruleEvaluation.factorBreakdown,
      ...(isAnomaly ? { "AI Behavioral Anomaly": mlRisk } : {})
    };

    return {
      ruleRisk,
      ruleTrust,
      isolationForestScore: ifs,
      normalizedAnomalyScore: nas,
      mlRisk,
      finalTrustScore,
      isAnomaly,
      mlServiceStatus,
      featuresUsed: sessionActivityTracker.extractFeatures(session),
      anomalyReasons: mlResult.anomalyReasons,
      riskFactors
    };
  }
}

export const hybridTrustService = new HybridTrustService();
export default hybridTrustService;
