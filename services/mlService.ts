/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard ML Anomaly Detection Service
 * Integrates with Python FastAPI Scikit-Learn Isolation Forest service,
 * with resilient offline fallback.
 */

import { trustConfig } from "./trustConfig";
import { ActiveSession } from "../src/types";
import { sessionActivityTracker, SessionBehavioralFeatures } from "./sessionActivityTracker";

export interface MLPredictionInput {
  login_hour: number;
  records_viewed: number;
  downloads_count: number;
  requests_per_minute: number;
  failed_operations: number;
  session_duration_minutes: number;
}

export interface MLPredictionResult {
  anomalyScore: number;     // 0.0 (normal) to 1.0 (highly anomalous)
  isAnomaly: boolean;       // boolean threshold (> 0.5)
  riskPenalty: number;      // score deduction (0 to 25)
  source: "fastapi" | "heuristic_fallback";
  details?: string;
}

class MLService {
  /**
   * Prepares feature vector from active session using the additive session activity tracker.
   */
  public extractFeatures(session: ActiveSession): SessionBehavioralFeatures {
    return sessionActivityTracker.extractFeatures(session);
  }

  /**
   * Evaluates anomaly score using FastAPI Isolation Forest microservice, falling back if unavailable.
   */
  public async getAnomalyScore(session: ActiveSession): Promise<MLPredictionResult> {
    const behavioral = this.extractFeatures(session);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), trustConfig.ml?.timeoutMs || 1500);

      let serviceUrl = trustConfig.ml?.serviceUrl || "http://127.0.0.1:8000/predict";
      if (!serviceUrl.endsWith("/predict")) {
        serviceUrl = serviceUrl.replace(/\/+$/, "") + "/predict";
      }

      const response = await fetch(serviceUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(behavioral),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const data = await response.json();
        const nas = typeof data.normalized_anomaly_score === "number"
          ? data.normalized_anomaly_score
          : (typeof data.anomalyScore === "number" ? data.anomalyScore : 0.0);
        
        const isAnomaly = Boolean(data.is_anomaly ?? data.isAnomaly);
        
        const riskPenalty = typeof data.ml_risk === "number"
          ? Math.round(data.ml_risk)
          : (typeof data.riskPenalty === "number" ? data.riskPenalty : Math.round(nas * 25));

        return {
          anomalyScore: Math.min(1.0, Math.max(0.0, parseFloat(nas.toFixed(4)))),
          isAnomaly,
          riskPenalty,
          source: "fastapi",
          details: isAnomaly
            ? `Isolation Forest detected behavioral anomaly (Score: ${nas.toFixed(3)}, Risk: ${riskPenalty})`
            : "Session behavioral pattern is within normal envelope"
        };
      } else {
        console.warn(`[mlService] ML microservice responded with status ${response.status}. Using fallback.`);
      }
    } catch (err: any) {
      console.warn(`[mlService] ML_SERVICE_UNAVAILABLE (${err?.message || "connection error"}). Activating offline fallback.`);
    }

    return this.calculateLocalIsolationForestHeuristic(session, behavioral);
  }

  /**
   * Resilient local anomaly estimator based on Isolation Forest anomaly weights.
   * Ensures zero disruption if Python service is stopped.
   */
  private calculateLocalIsolationForestHeuristic(session: ActiveSession, features: SessionBehavioralFeatures): MLPredictionResult {
    let rawScore = 0.05; // Base noise

    if (session.simulatedDeviceMismatch) rawScore += 0.28;
    if (session.simulatedIpMismatch) rawScore += 0.22;
    if (session.simulatedOutsideJurisdiction) rawScore += 0.20;
    if (session.simulatedSpamTriggered) rawScore += 0.18;
    if (session.simulatedNightAccess) rawScore += 0.12;
    if (session.simulatedIdleTriggered) rawScore += 0.10;
    if (features.failed_operations > 0) {
      rawScore += Math.min(0.35, features.failed_operations * 0.10);
    }
    if (features.requests_per_minute > 20) {
      rawScore += 0.25;
    }

    const anomalyScore = Math.min(1.0, Math.max(0.0, parseFloat(rawScore.toFixed(3))));
    const isAnomaly = anomalyScore >= 0.40;
    const riskPenalty = isAnomaly ? Math.round(anomalyScore * 25) : 0;

    return {
      anomalyScore,
      isAnomaly,
      riskPenalty,
      source: "heuristic_fallback",
      details: isAnomaly 
        ? `Local Isolation Forest fallback detected behavioral anomaly (Score: ${anomalyScore})`
        : "Session behavioral pattern is within normal envelope"
    };
  }
}

export const mlService = new MLService();
export default mlService;
