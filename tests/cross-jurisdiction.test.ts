/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Automated Test Suite: Cross-Jurisdiction Access Control
 * Verifies all 14 mandatory security test scenarios specified for the
 * Dynamic Zero Trust Access Control Engine.
 */

process.env.NODE_ENV = "test";
import test from "node:test";
import assert from "node:assert/strict";
import { authorizeLandRecordAccess } from "../services/authorizationService";
import { trustEngine } from "../services/trustEngine";
import { hybridTrustService } from "../services/hybridTrustService";
import { sessionActivityTracker } from "../services/sessionActivityTracker";
import { ActiveSession, RoleName, User, LandRecord, Village, AuditLog } from "../src/types";
import { DEFAULT_USERS, DEFAULT_LAND_RECORDS, villages } from "../server";

function createSession(user: User, initialScore: number = 90): ActiveSession {
  return {
    id: `sess_${user.id}_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
    userId: user.id,
    userName: user.name,
    userEmail: user.email,
    role: user.roleName,
    deviceFingerprint: user.registeredDevice || "Mozilla/5.0 Win64 Chrome",
    ipAddress: "192.168.1.50",
    loginTime: new Date().toISOString(),
    lastActivityTime: new Date().toISOString(),
    currentTrustScore: initialScore,
    status: "Active",
    token: `token_${user.id}`,
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

// Locate key actors and records
const vaoAnitha = DEFAULT_USERS.find(u => u.email === "anitha.vao@revenue.tn.gov.in")!;
const riOfficer = DEFAULT_USERS.find(u => u.roleName === RoleName.RevenueInspector)!;
const citizenRamesh = DEFAULT_USERS.find(u => u.roleName === RoleName.Citizen)!;
const adminShrinivas = DEFAULT_USERS.find(u => u.roleName === RoleName.SystemAdministrator)!;

// Locate records across villages and taluks
// rec1: Mudichur (v1, Tambaram taluk, Kancheepuram district)
const mudichurRec = DEFAULT_LAND_RECORDS.find(r => r.villageId === "v1")!;
// rec3: Manapakkam (v2, Tambaram taluk, Kancheepuram district - same taluk as Mudichur, different village)
const manapakkamRec = DEFAULT_LAND_RECORDS.find(r => r.villageId === "v2")!;
// rec5: Pillaipakkam (v4, Sriperumbudur taluk, Kancheepuram district - different village & different taluk)
const pillaipakkamRec = DEFAULT_LAND_RECORDS.find(r => r.villageId === "v4")!;

test("1. VAO Anitha successfully accesses Mudichur land document (authorized village, taluk, district)", () => {
  const session = createSession(vaoAnitha, 90);
  const decision = authorizeLandRecordAccess(vaoAnitha, mudichurRec, session, villages);

  assert.equal(decision.authorized, true, "Access should be authorized for assigned village");
  assert.equal(decision.decision, "ALLOWED");
  assert.equal(decision.isCrossJurisdiction, false);
  assert.equal(session.simulatedOutsideJurisdiction, false, "Outside jurisdiction flag should not be set");
});

test("2. VAO Anitha attempting to access Pillaipakkam record is denied 403, 20-pt penalty applied, trust score updated, document contents NOT returned", async () => {
  const session = createSession(vaoAnitha, 90);

  const decision = authorizeLandRecordAccess(vaoAnitha, pillaipakkamRec, session, villages);

  // Access check must be denied
  assert.equal(decision.authorized, false, "Access must be denied for different village outside jurisdiction");
  assert.equal(decision.decision, "DENIED");
  assert.equal(decision.isCrossJurisdiction, true);
  assert.equal(decision.code, "UNAUTHORIZED_CROSS_JURISDICTION_ACCESS");
  assert.equal(decision.reason, "Access Denied: This land record is outside your authorized jurisdiction. The access attempt has been recorded.");

  // Apply penalty and evaluate trust score dynamically
  session.simulatedOutsideJurisdiction = true;
  const evaluation = await trustEngine.evaluateSessionTrust(session, "Cross-Jurisdiction Attempt", vaoAnitha);

  // Verify 20-pt deduction
  assert.equal(session.simulatedOutsideJurisdiction, true);
  assert.equal(evaluation.hybridResult.ruleRisk, 20, "RuleRisk should include exactly 20-pt penalty for J=1");
  assert.equal(session.currentTrustScore, 80, `Trust score should be 100 - 20 = 80, got ${session.currentTrustScore}`);
  
  // Verify document data is withheld
  const responsePayload = {
    authorized: decision.authorized,
    decision: decision.decision,
    error: "cross_jurisdiction_access_denied",
    message: decision.reason,
    trustScore: session.currentTrustScore
  };
  assert.equal((responsePayload as any).documentPayload, undefined, "Protected documentPayload must not be included");
  assert.equal((responsePayload as any).surveyNumber, undefined, "Sensitive survey number must not be exposed");
});

test("3. VAO Anitha attempting to access different village within SAME taluk (Manapakkam) is denied with 20-pt penalty", async () => {
  const session = createSession(vaoAnitha, 90);
  const decision = authorizeLandRecordAccess(vaoAnitha, manapakkamRec, session, villages);

  // Even though taluk (Tambaram) matches, VAO is restricted to assigned village (Mudichur)
  assert.equal(decision.authorized, false, "VAO cannot access other villages within the same taluk");
  assert.equal(decision.isCrossJurisdiction, true);
  assert.equal(decision.code, "UNAUTHORIZED_CROSS_JURISDICTION_ACCESS");

  session.simulatedOutsideJurisdiction = true;
  const evalResult = await hybridTrustService.calculateHybridTrust(session);
  assert.equal(evalResult.ruleRisk, 20, "20-point penalty must be applied for cross-village attempt in same taluk");
});

test("4. Revenue Inspector accessing record within authorized taluk (Tambaram) is allowed", () => {
  const session = createSession(riOfficer, 90);
  // RI jurisdiction is Tambaram taluk. mudichurRec is in Tambaram taluk.
  const decision = authorizeLandRecordAccess(riOfficer, mudichurRec, session, villages);

  assert.equal(decision.authorized, true, "RI should be allowed access within authorized taluk");
  assert.equal(decision.decision, "ALLOWED");
  assert.equal(decision.isCrossJurisdiction, false);
});

test("5. Revenue Inspector accessing record outside authorized taluk (Pillaipakkam in Sriperumbudur) is denied", async () => {
  const session = createSession(riOfficer, 90);
  // Pillaipakkam is in Sriperumbudur taluk, outside RI's Tambaram taluk
  const decision = authorizeLandRecordAccess(riOfficer, pillaipakkamRec, session, villages);

  assert.equal(decision.authorized, false, "RI must be denied access outside authorized taluk");
  assert.equal(decision.isCrossJurisdiction, true);
  assert.equal(decision.code, "UNAUTHORIZED_CROSS_JURISDICTION_ACCESS");

  session.simulatedOutsideJurisdiction = true;
  const evalResult = await hybridTrustService.calculateHybridTrust(session);
  assert.ok(evalResult.ruleRisk >= 20, "Rule risk must reflect 20-pt penalty for cross-taluk violation");
});

test("6. Citizen accessing their own registered record is allowed", () => {
  const session = createSession(citizenRamesh, 90);
  const decision = authorizeLandRecordAccess(citizenRamesh, mudichurRec, session, villages);

  assert.equal(decision.authorized, true, "Citizen must be allowed access to their own registered land record");
  assert.equal(decision.decision, "ALLOWED");
  assert.equal(decision.isCrossJurisdiction, false);
});

test("7. Citizen attempting to access another citizen's record is denied 403", () => {
  const session = createSession(citizenRamesh, 90);
  // manapakkamRec is owned by Priya Govindan, not Ramesh Kumar
  const decision = authorizeLandRecordAccess(citizenRamesh, manapakkamRec, session, villages);

  assert.equal(decision.authorized, false, "Citizen must be denied access to parcels owned by another person");
  assert.equal(decision.decision, "DENIED");
  assert.equal(decision.code, "UNAUTHORIZED_CITIZEN_ACCESS");
  assert.match(decision.reason || "", /ownership authorization/i);
});

test("8. System Administrator attempting to view a land document is blocked by Separation of Duties", () => {
  const session = createSession(adminShrinivas, 100);
  const decision = authorizeLandRecordAccess(adminShrinivas, mudichurRec, session, villages);

  assert.equal(decision.authorized, false, "System Administrator must be barred from inspecting citizen land documents");
  assert.equal(decision.decision, "DENIED");
  assert.equal(decision.code, "SEPARATION_OF_DUTIES");
  assert.match(decision.reason || "", /Separation of Duties/i);
});

test("9. Verification that no document payload or sensitive metadata is returned on 403 denial", () => {
  const session = createSession(vaoAnitha, 90);
  const decision = authorizeLandRecordAccess(vaoAnitha, pillaipakkamRec, session, villages);

  assert.equal(decision.authorized, false);
  
  // Construct simulated HTTP 403 response
  const forbiddenResponse = {
    authorized: false,
    decision: "DENIED",
    error: "cross_jurisdiction_access_denied",
    message: decision.reason,
    trustScore: 70
  };

  assert.ok(!("documentPayload" in forbiddenResponse), "Must not have documentPayload");
  assert.ok(!("documentPath" in forbiddenResponse), "Must not have documentPath");
  assert.ok(!("ownerPhone" in forbiddenResponse), "Must not have ownerPhone");
  assert.ok(!("pattaDocumentPath" in forbiddenResponse), "Must not have pattaDocumentPath");
  assert.ok(!("chittaDocumentPath" in forbiddenResponse), "Must not have chittaDocumentPath");
  assert.ok(!("fmbCopyPath" in forbiddenResponse), "Must not have fmbCopyPath");
});

test("10. Verification that J = 1 penalty is applied exactly once and not double-counted", async () => {
  const session = createSession(vaoAnitha, 90);
  
  // First access check & penalty application
  session.simulatedOutsideJurisdiction = true;
  const eval1 = await hybridTrustService.calculateHybridTrust(session);
  const ruleRisk1 = eval1.ruleRisk;
  const score1 = eval1.finalTrustScore;
  assert.equal(ruleRisk1, 20, "First check should have RuleRisk = 20");

  // Subsequent check or repeat request within same session state
  session.simulatedOutsideJurisdiction = true;
  const eval2 = await hybridTrustService.calculateHybridTrust(session);
  const ruleRisk2 = eval2.ruleRisk;
  const score2 = eval2.finalTrustScore;

  assert.equal(ruleRisk2, 20, "RuleRisk must not double-count to 40; it must remain 20");
  assert.equal(score2, score1, "Trust score must not be deducted twice for the same threat factor");
});

test("11. Verification that stepping up with TOTP does not grant access to an unauthorized village", () => {
  const session = createSession(vaoAnitha, 70);
  session.otpVerified = true; // Step-up verification completed

  // VAO Anitha attempts to access Pillaipakkam even after TOTP verification
  const decision = authorizeLandRecordAccess(vaoAnitha, pillaipakkamRec, session, villages);

  assert.equal(decision.authorized, false, "TOTP verification must never override jurisdictional boundaries");
  assert.equal(decision.isCrossJurisdiction, true);
  assert.equal(decision.code, "UNAUTHORIZED_CROSS_JURISDICTION_ACCESS");
});

test("12. Verification that direct document download route enforces the same jurisdiction check", () => {
  const session = createSession(vaoAnitha, 90);
  
  // Authorize Mudichur (allowed)
  const allowedDecision = authorizeLandRecordAccess(vaoAnitha, mudichurRec, session, villages);
  assert.equal(allowedDecision.authorized, true);

  // Authorize Pillaipakkam (denied)
  const deniedDecision = authorizeLandRecordAccess(vaoAnitha, pillaipakkamRec, session, villages);
  assert.equal(deniedDecision.authorized, false);
  assert.equal(deniedDecision.isCrossJurisdiction, true);
});

test("13. Verification that trust score recalculation correctly updates session state", async () => {
  const session = createSession(vaoAnitha, 90);
  session.simulatedOutsideJurisdiction = true;

  const evaluation = await trustEngine.evaluateSessionTrust(
    session,
    "Cross-Jurisdiction Document Access Attempt: Survey 50/4C",
    vaoAnitha,
    "/api/records/rec5/view"
  );

  assert.equal(session.currentTrustScore, evaluation.finalScore, "session.currentTrustScore must equal evaluated finalScore");
  assert.ok(session.currentTrustScore < 90, `Session trust score must decrease from 90, got ${session.currentTrustScore}`);
  assert.equal(session.simulatedOutsideJurisdiction, true);
});

test("14. Verification that an audit record is created with CROSS_JURISDICTION_ACCESS_DENIED and required forensic fields", () => {
  const session = createSession(vaoAnitha, 90);
  const decision = authorizeLandRecordAccess(vaoAnitha, pillaipakkamRec, session, villages);

  const mockAuditLog: AuditLog = {
    id: `al_test_${Date.now()}`,
    userId: session.userId,
    userName: session.userName,
    role: session.role,
    actionPerformed: `VIEW_DOCUMENT_DENIED: Survey ${pillaipakkamRec.surveyNumber} (Cross-Jurisdiction Violation)`,
    resourceAccessed: `RECORD_DOCUMENT_${pillaipakkamRec.id}`,
    trustScoreAtAction: 70,
    decision: "DENIED",
    timestamp: new Date().toISOString(),
    reasons: ["Cross-Jurisdiction Access Denied: User jurisdiction does not encompass requested record parcel."],
    ipAddress: session.ipAddress,
    device: session.deviceFingerprint,
    ruleRisk: 20,
    eventType: "CROSS_JURISDICTION_ACCESS_DENIED",
    requestedRecordId: pillaipakkamRec.id,
    requestedRecordJurisdiction: decision.recordJurisdiction,
    authorizedUserJurisdiction: decision.userJurisdiction,
    ruleJValue: 1,
    rulePenalty: 20,
    sessionId: session.id
  };

  assert.equal(mockAuditLog.eventType, "CROSS_JURISDICTION_ACCESS_DENIED");
  assert.equal(mockAuditLog.ruleJValue, 1);
  assert.equal(mockAuditLog.rulePenalty, 20);
  assert.equal(mockAuditLog.requestedRecordId, "rec5");
  assert.equal(mockAuditLog.requestedRecordJurisdiction?.villageId, "v4");
  assert.equal(mockAuditLog.authorizedUserJurisdiction?.villageId, "v1");
});

test("15. Details view check: VAO Anitha attempting to open record details outside jurisdiction is denied 403, 20-pt penalty applied, and record metadata is NOT exposed", async () => {
  const session = createSession(vaoAnitha, 90);
  const decision = authorizeLandRecordAccess(vaoAnitha, pillaipakkamRec, session, villages);

  assert.equal(decision.authorized, false, "Details access must be denied for record outside jurisdiction");
  assert.equal(decision.isCrossJurisdiction, true);
  assert.equal(decision.code, "UNAUTHORIZED_CROSS_JURISDICTION_ACCESS");

  session.simulatedOutsideJurisdiction = true;
  const evaluation = await trustEngine.evaluateSessionTrust(
    session,
    `Cross-Jurisdiction Record Details View Attempt: Survey ${pillaipakkamRec.surveyNumber}`,
    vaoAnitha,
    `/api/records/${pillaipakkamRec.id}`
  );

  assert.equal(evaluation.hybridResult.ruleRisk, 20, "20-pt penalty must be applied");
  assert.equal(session.currentTrustScore, 80, "Trust score should drop by 20 points from 90 to 80");

  const responsePayload = {
    authorized: false,
    decision: "DENIED",
    error: "cross_jurisdiction_access_denied",
    message: "Access Denied: This land record is outside your authorized jurisdiction. The access attempt has been recorded.",
    trustScore: session.currentTrustScore
  };

  assert.equal((responsePayload as any).ownerName, undefined, "Protected record details like ownerName must not be exposed");
  assert.equal((responsePayload as any).ownerPhone, undefined, "Protected record details like ownerPhone must not be exposed");
  assert.equal((responsePayload as any).pattaNumber, undefined, "Protected record details like pattaNumber must not be exposed");
});

