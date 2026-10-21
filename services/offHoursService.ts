/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Real-Time Off-Hours Night Access Detection Service
 * Validates access against Indian Standard Time (IST) - Asia/Kolkata.
 * 
 * Policy:
 * - Allowed Hours: 07:00:00 AM IST through 06:59:59 PM IST (07:00:00 - 18:59:59)
 * - Restricted Hours: 07:00:00 PM IST (19:00:00) through 06:59:59 AM IST (< 07:00:00)
 */

export interface IstTimeCheckResult {
  isOffHours: boolean;
  hour: number;
  minute: number;
  second: number;
  formattedIstTime: string;
  formattedIstFull: string;
  timeOnlyIst: string;
  dateOnlyIst: string;
  isoTimestamp: string;
  reasons: string[];
}

/**
 * Evaluates whether a given timestamp (or current time if omitted) falls within
 * the restricted Off-Hours Night Access window (19:00 to 07:00 IST).
 * 
 * Timezone: Asia/Kolkata
 */
export function checkIstOffHours(dateInput?: Date | string | number): IstTimeCheckResult {
  const d = dateInput !== undefined ? new Date(dateInput) : new Date();

  // Extract hour, minute, second strictly in Asia/Kolkata timezone
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "Asia/Kolkata",
    hour: "numeric",
    minute: "numeric",
    second: "numeric",
    hour12: false
  }).formatToParts(d);

  const partMap: Record<string, string> = {};
  for (const p of parts) {
    partMap[p.type] = p.value;
  }

  const hour = parseInt(partMap.hour, 10);
  const minute = parseInt(partMap.minute, 10);
  const second = parseInt(partMap.second, 10);

  // Restricted if time is at/after 7:00 PM (19:00:00) OR before 7:00 AM (07:00:00) IST
  const isOffHours = hour < 7 || hour >= 19;

  // Format 12-hour time in IST (e.g. "07:30:15 PM IST")
  const timeOnlyIst = new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    hour: "numeric",
    minute: "numeric",
    second: "numeric",
    hour12: true
  }).format(d) + " IST";

  const dateOnlyIst = new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "short",
    year: "numeric"
  }).format(d);

  const formattedIstFull = `${dateOnlyIst}, ${timeOnlyIst}`;

  const reasons: string[] = [];
  if (isOffHours) {
    reasons.push(
      `Off-Hours Night Access: Login attempted at ${timeOnlyIst}. Access to TrustGuard is restricted between 7:00 PM and 7:00 AM IST.`
    );
  }

  return {
    isOffHours,
    hour,
    minute,
    second,
    formattedIstTime: timeOnlyIst,
    formattedIstFull,
    timeOnlyIst,
    dateOnlyIst,
    isoTimestamp: d.toISOString(),
    reasons
  };
}
