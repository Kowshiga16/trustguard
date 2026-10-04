/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Hybrid Trust Service
 * Combines:
 *  1. Existing Rule-Based Trust Evaluation (Protects existing rules and baseline)
 *  2. Scikit-Learn Isolation Forest ML Anomaly Detection Service
 * 
 * FinalTrustScore = max(0, 100 - RuleRisk - MLRisk)
 * 
 * Strictly additive. The existing Rule-Based engine is completely untouched and reused.
 */

import { ActiveSession } from "../src/types";
import { trustEngine } from "./trustEngine";
import { sessionActivityTracker, SessionBehavioralFeatures } from "./sessionActivityTracker";
import { trustConfig } from "./trustConfig";

export interface HybridTrustScoreResult {
  ruleRisk: number;
  ruleTrust: number;
  isolationForestScore: number;
  normalizedAnomalyScore: number;
  mlRisk: number;
  finalTrustScore: number;
  isAnomaly: boolean;
  mlServiceStatus: "AVAILABLE" | "ML_SERVICE_UNAVAILABLE";
  featuresUsed?: SessionBehavioralFeatures;
}

export interface MLServiceResponse {
  isolation_forest_score: number;
  is_anomaly: boolean;
  normalized_anomaly_score: number;
  ml_risk: number;
}

class HybridTrustService {
  /**
   * Evaluates the hybrid trust score by querying the FastAPI Isolation Forest service
   * and reusing the existing rule engine calculation.
   */
  public async calculateHybridTrust(session: ActiveSession): Promise<HybridTrustScoreResult> {
    // 1. Existing Rule-Based result (PROTECTED - directly reused)
    const ruleTrust = trustEngine.calculateRuleBasedScore(session);
    const ruleRisk = Math.max(0, 100 - ruleTrust);

    // 2. Extract behavioral features from additive tracker
    const features = sessionActivityTracker.extractFeatures(session);

    // 3. Query Python FastAPI Isolation Forest service
    let mlScore = 0.0;
    let nas = 0.0;
    let mlRisk = 0.0;
    let isAnomaly = false;
    let mlServiceStatus: "AVAILABLE" | "ML_SERVICE_UNAVAILABLE" = "AVAILABLE";

    try {
      let mlUrl = process.env.ML_SERVICE_URL || "http://127.0.0.1:8000/predict";
      if (!mlUrl.endsWith("/predict")) {
        mlUrl = mlUrl.replace(/\/+$/, "") + "/predict";
      }
      const controller = new AbortController();
      const timeoutMs = trustConfig.ml?.timeoutMs || 1500;
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      const response = await fetch(mlUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(features),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const data = (await response.json()) as MLServiceResponse;
        mlScore = typeof data.isolation_forest_score === "number" ? data.isolation_forest_score : 0.0;
        nas = typeof data.normalized_anomaly_score === "number" ? data.normalized_anomaly_score : 0.0;
        mlRisk = typeof data.ml_risk === "number" ? data.ml_risk : Math.round(25.0 * nas * 100) / 100;
        isAnomaly = Boolean(data.is_anomaly);
      } else {
        console.warn(`[HybridTrustService] ML service returned HTTP ${response.status}. Falling back to Rule Risk only.`);
        mlServiceStatus = "ML_SERVICE_UNAVAILABLE";
      }
    } catch (err: any) {
      console.warn(`[HybridTrustService] ML_SERVICE_UNAVAILABLE: ${err?.message || "Failed to reach ML service"}. Running on Rule Risk only.`);
      mlServiceStatus = "ML_SERVICE_UNAVAILABLE";
      mlRisk = 0.0;
      nas = 0.0;
      isAnomaly = false;
    }

    // 4. Hybrid Trust Calculation: FinalTrustScore = max(0, 100 - RuleRisk - MLRisk)
    const finalTrustScore = Math.min(100, Math.max(0, Math.round(100 - ruleRisk - mlRisk)));

    return {
      ruleRisk,
      ruleTrust,
      isolationForestScore: mlScore,
      normalizedAnomalyScore: nas,
      mlRisk,
      finalTrustScore,
      isAnomaly,
      mlServiceStatus,
      featuresUsed: features
    };
  }
}

export const hybridTrustService = new HybridTrustService();
export default hybridTrustService;
