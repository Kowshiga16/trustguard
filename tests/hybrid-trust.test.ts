/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Unit tests for TrustGuard Hybrid Trust Service & Isolation Forest Integration
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { hybridTrustService } from "../services/hybridTrustService";
import { sessionActivityTracker } from "../services/sessionActivityTracker";
import { trustEngine } from "../services/trustEngine";
import { ActiveSession, RoleName } from "../src/types";

function createTestSession(id: string = "test_sess_001"): ActiveSession {
  return {
    id,
    userId: "user_raj",
    userName: "Raj Kumar",
    userEmail: "raj.kumar@revenue.tn.gov.in",
    role: RoleName.Tahsildar,
    deviceFingerprint: "browser-chrome-macOS",
    ipAddress: "192.168.1.104",
    loginTime: new Date(Date.now() - 15 * 60000).toISOString(), // 15 mins ago
    lastActivityTime: new Date().toISOString(),
    currentTrustScore: 75,
    status: "Active",
    simulatedDeviceMismatch: false,
    simulatedIpMismatch: false,
    simulatedNightAccess: false,
    simulatedOutsideJurisdiction: false,
    simulatedSpamTriggered: false,
    simulatedIdleTriggered: false,
    failedActionCount: 0,
    otpVerified: false
  };
}

test('Hybrid Trust: Formula FinalTrustScore = max(0, 100 - RuleRisk - MLRisk)', async () => {
  const session = createTestSession("sess_normal");
  
  // Record normal activity
  sessionActivityTracker.recordRecordView(session.id, 5);
  sessionActivityTracker.recordDownload(session.id);
  sessionActivityTracker.recordRequest(session.id);

  const result = await hybridTrustService.calculateHybridTrust(session);

  // Validate fields exist
  assert.ok(typeof result.ruleRisk === "number", "ruleRisk should be a number");
  assert.ok(typeof result.ruleTrust === "number", "ruleTrust should be a number");
  assert.ok(typeof result.isolationForestScore === "number", "isolationForestScore should be a number");
  assert.ok(typeof result.normalizedAnomalyScore === "number", "normalizedAnomalyScore should be a number");
  assert.ok(typeof result.mlRisk === "number", "mlRisk should be a number");
  assert.ok(typeof result.finalTrustScore === "number", "finalTrustScore should be a number");
  assert.ok(typeof result.isAnomaly === "boolean", "isAnomaly should be a boolean");

  // Formula validation
  const expectedFinal = Math.min(100, Math.max(0, Math.round(100 - result.ruleRisk - result.mlRisk)));
  assert.equal(result.finalTrustScore, expectedFinal, "FinalTrustScore must equal max(0, 100 - RuleRisk - MLRisk)");
  
  // Rule risk must match 100 - ruleTrust
  assert.equal(result.ruleRisk, Math.max(0, 100 - result.ruleTrust));
  
  // ML risk bound: max 25
  assert.ok(result.mlRisk >= 0 && result.mlRisk <= 25, "mlRisk must be bounded between 0 and 25");
});

test('Hybrid Trust: Anomaly Detection with High Behavioral Deviation', async () => {
  const session = createTestSession("sess_deviant");

  // Inject massive behavioral anomaly
  sessionActivityTracker.recordRecordView(session.id, 180);
  for (let i = 0; i < 40; i++) {
    sessionActivityTracker.recordDownload(session.id);
  }
  for (let i = 0; i < 80; i++) {
    sessionActivityTracker.recordRequest(session.id);
  }
  for (let i = 0; i < 10; i++) {
    sessionActivityTracker.recordFailedOperation(session.id);
  }

  const result = await hybridTrustService.calculateHybridTrust(session);
  
  // In the presence of the live FastAPI service, it will evaluate as anomaly
  if (result.mlServiceStatus === "AVAILABLE") {
    assert.equal(result.isAnomaly, true, "Massive spike should trigger isAnomaly=true");
    assert.ok(result.mlRisk >= 15, "ML risk should be high for abnormal behavioral profile");
    assert.ok(result.normalizedAnomalyScore > 0.5, "Normalized Anomaly Score should be > 0.5");
  }
});

test('Hybrid Trust: Existing Rule Penalties are Reused Without Alteration', async () => {
  const session = createTestSession("sess_threats");
  session.simulatedDeviceMismatch = true; // -20
  session.simulatedIpMismatch = true;     // -15

  const directRuleScore = trustEngine.calculateRuleBasedScore(session);
  assert.equal(directRuleScore, 65, "100 baseline - 20 - 15 = 65");

  const hybridResult = await hybridTrustService.calculateHybridTrust(session);
  assert.equal(hybridResult.ruleTrust, directRuleScore, "Hybrid service must reuse exact rule score from trustEngine");
  assert.equal(hybridResult.ruleRisk, 35, "Rule risk must equal 100 - 65 = 35");
});
