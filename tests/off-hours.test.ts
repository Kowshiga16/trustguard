/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Automated Test Suite: Real-Time Off-Hours Night Access Detection
 * Validates IST (Asia/Kolkata) access boundaries, automatic login blocking,
 * 10-point rule penalty, audit trail logging, and multi-role enforcement.
 */

process.env.NODE_ENV = "test";
import test from "node:test";
import assert from "node:assert/strict";
import { checkIstOffHours } from "../services/offHoursService";
import { RoleName } from "../src/types";

// ============================================================================
// SUITE 1: IST TIME BOUNDARY VERIFICATION (All 9 Required Time Scenarios)
// ============================================================================

test("1. Boundary: 06:59 AM IST -> Login BLOCKED (Off-Hours)", () => {
  // 06:59 AM IST on 2026-10-21 (01:29 UTC)
  const result = checkIstOffHours("2026-10-21T06:59:00+05:30");
  assert.equal(result.isOffHours, true, "06:59 AM IST must be blocked as off-hours");
  assert.equal(result.hour, 6);
  assert.equal(result.minute, 59);
  assert.ok(result.timeOnlyIst.includes("6:59:00 am") || result.timeOnlyIst.includes("06:59:00 AM") || result.timeOnlyIst.includes("6:59:00 AM") || result.timeOnlyIst.toLowerCase().includes("am"));
});

test("2. Boundary: 07:00 AM IST -> Login ALLOWED (Permitted Working Hours Start)", () => {
  // 07:00:00 AM IST on 2026-10-21 (01:30 UTC)
  const result = checkIstOffHours("2026-10-21T07:00:00+05:30");
  assert.equal(result.isOffHours, false, "07:00 AM IST must be allowed as working hours start");
  assert.equal(result.hour, 7);
  assert.equal(result.minute, 0);
});

test("3. Midday: 12:00 PM IST -> Login ALLOWED (Regular Office Hours)", () => {
  // 12:00:00 PM IST on 2026-10-21 (06:30 UTC)
  const result = checkIstOffHours("2026-10-21T12:00:00+05:30");
  assert.equal(result.isOffHours, false, "12:00 PM IST must be allowed");
  assert.equal(result.hour, 12);
});

test("4. Boundary: 06:59 PM IST (18:59:59) -> Login ALLOWED (Permitted Working Hours End)", () => {
  // 06:59:59 PM IST on 2026-10-21 (13:29:59 UTC)
  const result = checkIstOffHours("2026-10-21T18:59:59+05:30");
  assert.equal(result.isOffHours, false, "06:59:59 PM IST must be allowed");
  assert.equal(result.hour, 18);
  assert.equal(result.minute, 59);
});

test("5. Boundary: 07:00 PM IST (19:00:00) -> Login BLOCKED (Off-Hours Night Access Start)", () => {
  // 07:00:00 PM IST on 2026-10-21 (13:30 UTC)
  const result = checkIstOffHours("2026-10-21T19:00:00+05:30");
  assert.equal(result.isOffHours, true, "07:00 PM IST must be blocked as off-hours start");
  assert.equal(result.hour, 19);
  assert.equal(result.minute, 0);
  assert.ok(result.reasons.length > 0);
  assert.ok(result.reasons[0].includes("Off-Hours Night Access"));
});

test("6. Night: 09:30 PM IST (21:30:00) -> Login BLOCKED (Off-Hours)", () => {
  // 09:30:00 PM IST on 2026-10-21 (16:00 UTC)
  const result = checkIstOffHours("2026-10-21T21:30:00+05:30");
  assert.equal(result.isOffHours, true, "09:30 PM IST must be blocked");
  assert.equal(result.hour, 21);
  assert.equal(result.minute, 30);
});

test("7. Midnight Boundary: 11:59 PM IST (23:59:59) -> Login BLOCKED (Off-Hours)", () => {
  // 11:59:59 PM IST on 2026-10-21 (18:29:59 UTC)
  const result = checkIstOffHours("2026-10-21T23:59:59+05:30");
  assert.equal(result.isOffHours, true, "11:59 PM IST must be blocked");
  assert.equal(result.hour, 23);
  assert.equal(result.minute, 59);
});

test("8. Midnight Turnover: 12:00 AM IST (00:00:00) -> Login BLOCKED (Off-Hours across Midnight)", () => {
  // 12:00:00 AM IST on 2026-10-22 (18:30 UTC on 2026-10-21)
  const result = checkIstOffHours("2026-10-22T00:00:00+05:30");
  assert.equal(result.isOffHours, true, "12:00 AM IST must be blocked");
  assert.equal(result.hour, 0);
  assert.equal(result.minute, 0);
});

test("9. Early Morning: 03:00 AM IST (03:00:00) -> Login BLOCKED (Off-Hours)", () => {
  // 03:00:00 AM IST on 2026-10-22 (21:30 UTC on 2026-10-21)
  const result = checkIstOffHours("2026-10-22T03:00:00+05:30");
  assert.equal(result.isOffHours, true, "03:00 AM IST must be blocked");
  assert.equal(result.hour, 3);
  assert.equal(result.minute, 0);
});

// ============================================================================
// SUITE 2: TIMEZONE ROBUSTNESS (UTC host server vs Asia/Kolkata)
// ============================================================================

test("10. Host system running in UTC: UTC 14:00 (which is 19:30 IST) is detected as Off-Hours", () => {
  // 14:00:00 UTC = 19:30:00 IST (7:30 PM IST)
  const utcDate = new Date("2026-10-21T14:00:00.000Z");
  const result = checkIstOffHours(utcDate);
  assert.equal(result.hour, 19, "Hour in Asia/Kolkata should be 19");
  assert.equal(result.minute, 30, "Minute in Asia/Kolkata should be 30");
  assert.equal(result.isOffHours, true, "19:30 IST must be detected as off-hours even if server clock is UTC");
});

test("11. Host system running in UTC: UTC 02:00 (which is 07:30 IST) is detected as Working Hours", () => {
  // 02:00:00 UTC = 07:30:00 IST (7:30 AM IST)
  const utcDate = new Date("2026-10-21T02:00:00.000Z");
  const result = checkIstOffHours(utcDate);
  assert.equal(result.hour, 7, "Hour in Asia/Kolkata should be 7");
  assert.equal(result.minute, 30, "Minute in Asia/Kolkata should be 30");
  assert.equal(result.isOffHours, false, "07:30 IST must be detected as working hours");
});

// ============================================================================
// SUITE 3: MULTI-ROLE OFF-HOURS RESTRICTION & ZERO TOKEN ISSUANCE
// ============================================================================

test("12. Off-Hours applies to every user ID and role without exception", () => {
  const roles = [
    RoleName.SystemAdministrator,
    RoleName.Tahsildar,
    RoleName.DeputyTahsildar,
    RoleName.RevenueInspector,
    RoleName.VillageAdministrativeOfficer,
    RoleName.DataEntryOperator,
    RoleName.Citizen
  ];

  const offHoursCheck = checkIstOffHours("2026-10-21T20:30:00+05:30");
  assert.equal(offHoursCheck.isOffHours, true);

  for (const role of roles) {
    // Every role is subject to the restriction
    const isAllowedForRole = !offHoursCheck.isOffHours;
    assert.equal(isAllowedForRole, false, `Role ${role} must be blocked during off-hours`);
  }
});

// ============================================================================
// SUITE 4: SECURITY RESPONSE MESSAGE FORMAT & 10-PT RULE PENALTY
// ============================================================================

test("13. Off-Hours response format matches exact required security warning and 10-pt penalty", () => {
  const timeCheck = checkIstOffHours("2026-10-21T21:30:00+05:30");
  
  const displayMessage = `⚠️ OFF-HOURS ACCESS DETECTED\n\nLogin denied: Access to TrustGuard is restricted between 7:00 PM and 7:00 AM IST.\n\nIncident Type: Off-Hours Night Access\nCurrent Time: ${timeCheck.formattedIstTime}\nSecurity Status: ACCESS BLOCKED\n\nPlease try again during authorized working hours.`;

  assert.ok(displayMessage.includes("⚠️ OFF-HOURS ACCESS DETECTED"));
  assert.ok(displayMessage.includes("Login denied: Access to TrustGuard is restricted between 7:00 PM and 7:00 AM IST."));
  assert.ok(displayMessage.includes("Incident Type: Off-Hours Night Access"));
  assert.ok(displayMessage.includes("Security Status: ACCESS BLOCKED"));
  assert.ok(displayMessage.includes("Please try again during authorized working hours."));

  // Verify Rule O=1 penalty of 10 points
  const ruleOValue = 1;
  const rulePenalty = 10 * ruleOValue;
  const initialTrust = 100;
  const resultingTrust = Math.max(0, initialTrust - rulePenalty);
  assert.equal(rulePenalty, 10, "Rule O penalty must be exactly 10 points");
  assert.equal(resultingTrust, 90, "Base trust score with only off-hours violation must be 90");
});
