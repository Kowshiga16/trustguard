/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Automated Unit Tests:
 * 1. Configurable Trust Score Thresholds
 * 2. Alert Trigger Conditions & Policy Mapping
 * 3. Alert Deduplication & Cooldown Logic
 * 4. NodeMailer Service Mock / Delivery Resilience
 * 5. ML Anomaly Score Integration
 */

process.env.NODE_ENV = "test";
import test from 'node:test';
import assert from 'node:assert/strict';
import { trustConfig, RiskLevel, getRiskLevel, getPolicyDecisionForRisk, isRiskLevelAlertable, getRoleOtpThreshold } from '../services/trustConfig';
import { emailService } from '../services/emailService';
import { alertManager } from '../services/alertManager';
import { trustEngine } from '../services/trustEngine';
import { ActiveSession, RoleName } from '../src/types';

function createMockSession(overrides: Partial<ActiveSession> = {}): ActiveSession {
  return {
    id: `sess_test_${Date.now()}`,
    userId: "u_test_tehsildar",
    userName: "Raj Kumar",
    userEmail: "raj.kumar@revenue.tn.gov.in",
    role: RoleName.Tahsildar,
    deviceFingerprint: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
    ipAddress: "192.168.1.104",
    loginTime: new Date().toISOString(),
    lastActivityTime: new Date().toISOString(),
    currentTrustScore: 85,
    status: "Active",
    simulatedDeviceMismatch: false,
    simulatedIpMismatch: false,
    simulatedNightAccess: false,
    simulatedOutsideJurisdiction: false,
    simulatedSpamTriggered: false,
    simulatedIdleTriggered: false,
    failedActionCount: 0,
    otpVerified: false,
    ...overrides
  };
}

test('1. Configurable Trust Thresholds and Risk Levels', () => {
  assert.equal(getRiskLevel(100), RiskLevel.LOW);
  assert.equal(getRiskLevel(85), RiskLevel.LOW);
  assert.equal(getRiskLevel(80), RiskLevel.LOW);
  assert.equal(getRiskLevel(79), RiskLevel.MEDIUM);
  assert.equal(getRiskLevel(65), RiskLevel.MEDIUM);
  assert.equal(getRiskLevel(60), RiskLevel.MEDIUM);
  assert.equal(getRiskLevel(59), RiskLevel.HIGH);
  assert.equal(getRiskLevel(55), RiskLevel.HIGH);
  assert.equal(getRiskLevel(40), RiskLevel.HIGH);
  assert.equal(getRiskLevel(39), RiskLevel.CRITICAL);
  assert.equal(getRiskLevel(20), RiskLevel.CRITICAL);
  assert.equal(getRiskLevel(-1), RiskLevel.CRITICAL);

  // Alertable risk levels
  assert.equal(isRiskLevelAlertable(RiskLevel.LOW), false);
  assert.equal(isRiskLevelAlertable(RiskLevel.MEDIUM), false);
  assert.equal(isRiskLevelAlertable(RiskLevel.HIGH), true);
  assert.equal(isRiskLevelAlertable(RiskLevel.CRITICAL), true);
});

test('2. Policy Decision Mapping', () => {
  const lowPolicy = getPolicyDecisionForRisk(RiskLevel.LOW);
  assert.equal(lowPolicy, "FULL_ACCESS");

  const mediumPolicy = getPolicyDecisionForRisk(RiskLevel.MEDIUM);
  assert.equal(mediumPolicy, "RESTRICTED");

  const highPolicy = getPolicyDecisionForRisk(RiskLevel.HIGH);
  assert.equal(highPolicy, "READ_ONLY");

  const criticalPolicy = getPolicyDecisionForRisk(RiskLevel.CRITICAL);
  assert.equal(criticalPolicy, "BLOCKED");
});

test('3. Alert Trigger and Deduplication / Cooldown Logic', () => {
  alertManager.clearCooldown();
  const session = createMockSession({ currentTrustScore: 100 });

  // Scenario A: Score drops from 100 (LOW) to 55 (HIGH)
  session.simulatedDeviceMismatch = true;
  session.simulatedIpMismatch = true;

  const result1 = alertManager.evaluateAlert(
    session,
    100, // previousScore
    55,  // currentScore
    undefined,
    "/api/records"
  );

  assert.equal(result1.shouldAlert, true, "Should trigger alert when crossing from LOW to HIGH");
  assert.equal(result1.isSuppressedByCooldown, false);
  assert.equal(result1.riskLevel, RiskLevel.HIGH);
  assert.ok(result1.reasons.length > 0, "Reasons should be extracted");
  assert.ok(result1.securityAlert !== undefined);
  assert.ok(result1.auditEntry !== undefined);

  // Scenario B: Minor fluctuation from 55 to 54 on next API call
  // Should be suppressed by cooldown / deduplication!
  const result2 = alertManager.evaluateAlert(
    session,
    55,  // previousScore
    54,  // currentScore
    undefined,
    "/api/records"
  );

  assert.equal(result2.shouldAlert, false, "Duplicate email must NOT be sent for tiny fluctuation (55 -> 54)");
  assert.equal(result2.isSuppressedByCooldown, true, "Must be flagged as suppressed by cooldown");

  // Scenario C: Threat escalates further: 54 -> 30 (CRITICAL)
  session.simulatedOutsideJurisdiction = true;
  const result3 = alertManager.evaluateAlert(
    session,
    54,  // previousScore
    30,  // currentScore
    undefined,
    "/api/records"
  );

  assert.equal(result3.shouldAlert, true, "Must trigger alert when escalating to CRITICAL even within cooldown");
  assert.equal(result3.riskLevel, RiskLevel.CRITICAL);
});

test('4. NodeMailer Service Mock / Resilient Email Dispatch', async () => {
  const alertData = {
    userName: "Raj Kumar",
    userEmail: "raj.kumar@revenue.tn.gov.in",
    userRole: "Tahsildar",
    previousTrustScore: 87,
    currentTrustScore: 48,
    riskLevel: "HIGH",
    reasons: [
      "Unrecognized device fingerprint detected",
      "Unusual IP address / network route change detected"
    ],
    ipAddress: "10.244.52.8",
    location: "Tambaram, Kancheepuram (Official Office)",
    device: "Chrome 122 on Windows 11 (Untrusted Device)",
    timestamp: new Date().toISOString(),
    policyDecision: "READ_ONLY",
    requestResource: "/api/records"
  };

  const sendResult = await emailService.sendTrustScoreAlert(alertData);
  assert.ok(typeof sendResult.success === "boolean", "Email service should return success boolean without crashing");
  assert.ok(sendResult.messageId || sendResult.simulated || sendResult.error, "Should return a messageId, simulated flag, or handled error");
});

test('5. Dynamic Trust Engine Rule Scoring & ML Blending', async () => {
  const session = createMockSession();

  // Baseline stable session
  const baseScore = trustEngine.calculateRuleBasedScore(session);
  assert.equal(baseScore, 100, "Base score without threat flags should be 100");

  // Threat toggled: device mismatch (-20) and IP mismatch (-15)
  session.simulatedDeviceMismatch = true;
  session.simulatedIpMismatch = true;

  const degradedScore = trustEngine.calculateRuleBasedScore(session);
  assert.equal(degradedScore, 65, "100 - 20 - 15 = 65");

  // Full session evaluation pipeline combining rule score (65) and ML anomaly penalty
  const evalResult = await trustEngine.evaluateSessionTrust(session, "Threat Simulation", undefined, "/api/test");
  assert.ok(evalResult.hybridResult.mlRisk >= 0, "ML anomaly penalty should be applied");
  assert.ok(evalResult.riskLevel === RiskLevel.MEDIUM || evalResult.riskLevel === RiskLevel.HIGH, "Degraded score maps to Medium or High Risk");
  assert.ok(evalResult.reasons.length >= 2, "Should include device mismatch and IP shift reasons");
  assert.ok(evalResult.policyDecision.length > 0);
});

test('6. Role-Based Low-Trust Thresholds for Step-Up Challenge', () => {
  assert.equal(getRoleOtpThreshold("System Administrator"), 60);
  assert.equal(getRoleOtpThreshold("Tahsildar"), 60);
  assert.equal(getRoleOtpThreshold("Deputy Tahsildar"), 60);
  assert.equal(getRoleOtpThreshold("Revenue Inspector (RI)"), 60);
  assert.equal(getRoleOtpThreshold("VAO / Village Officer"), 60);
  assert.equal(getRoleOtpThreshold("Data Entry Operator"), 60);
  assert.equal(getRoleOtpThreshold("Citizen / Land Owner"), 50);
  assert.equal(getRoleOtpThreshold("Unknown Officer Role"), trustConfig.thresholds.mediumRiskMin);
});

test('7. NodeMailer OTP Generation and Resilient Delivery', async () => {
  const otpData = {
    userName: "Raj Kumar",
    userEmail: "raj.kumar@revenue.tn.gov.in",
    userRole: "Tahsildar",
    otpCode: "654321",
    currentTrustScore: 54,
    roleThreshold: 70,
    expiresInMinutes: 10,
    reasons: [
      "Mid-Session IP Route Drift detected (-20)",
      "Unrecognized device hardware signature (-25)"
    ],
    triggerContext: "Threat Simulation: Role-Based Low Trust Challenge",
    ipAddress: "10.244.52.8",
    device: "Chrome 122 on Windows 11"
  };

  const otpResult = await emailService.sendOtpEmail(otpData);
  assert.ok(typeof otpResult.success === "boolean", "OTP email sending must return boolean without throwing");
  assert.equal(otpResult.otpCode, "654321", "Must return the generated OTP code");
  assert.ok(otpResult.simulated !== undefined, "Must indicate simulation or live transport mode");
});
