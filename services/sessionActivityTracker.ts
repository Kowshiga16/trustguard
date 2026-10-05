/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Session Activity & Behavioral Monitor
 * Real-time behavioral metric tracking for Scikit-Learn Isolation Forest analysis:
 * 1. login_hour (working hour distribution: 7 to 19 baseline)
 * 2. records_viewed (cumulative land documents viewed in session)
 * 3. downloads_count (cumulative documents exported/downloaded)
 * 4. requests_per_minute (rolling 60-second request velocity)
 * 5. failed_operations (unauthorized actions / permission denials)
 * 6. session_duration_minutes (session elapsed duration)
 */

import { ActiveSession } from "../src/types";
import { getRoleDocumentPolicy } from "./trustConfig";

export interface SessionBehavioralFeatures {
  login_hour: number;
  records_viewed: number;
  downloads_count: number;
  requests_per_minute: number;
  failed_operations: number;
  session_duration_minutes: number;
  ip_mismatch?: number;
  device_mismatch?: number;
}

interface InternalSessionState {
  recordsViewed: number;
  downloadsCount: number;
  requestTimestamps: number[];
  failedOperations: number;
  rateLimitExceeded: boolean;
  distinctDocumentIds: Set<string>;
}

class SessionActivityTracker {
  private sessions = new Map<string, InternalSessionState>();

  private getOrCreate(sessionId: string): InternalSessionState {
    let state = this.sessions.get(sessionId);
    if (!state) {
      state = {
        recordsViewed: 0,
        downloadsCount: 0,
        requestTimestamps: [],
        failedOperations: 0,
        rateLimitExceeded: false,
        distinctDocumentIds: new Set<string>()
      };
      this.sessions.set(sessionId, state);
    }
    return state;
  }

  /**
   * Tracks an incoming API request within rolling 60-second window.
   */
  public recordRequest(sessionId: string): void {
    const state = this.getOrCreate(sessionId);
    const now = Date.now();
    state.requestTimestamps.push(now);
    state.requestTimestamps = state.requestTimestamps.filter(t => now - t <= 60000);
  }

  /**
   * Tracks document viewing activity (NOT a download).
   */
  public recordRecordView(sessionId: string, count: number = 1, docId?: string): void {
    const state = this.getOrCreate(sessionId);
    state.recordsViewed += count;
    if (docId) {
      state.distinctDocumentIds.add(docId);
    }
  }

  /**
   * Tracks an explicit document file download / export action.
   */
  public recordDownload(sessionId: string, count: number = 1): void {
    const state = this.getOrCreate(sessionId);
    state.downloadsCount += count;
  }

  /**
   * Tracks an authorization failure, invalid attempt, or access denial.
   */
  public recordFailedOperation(sessionId: string): void {
    const state = this.getOrCreate(sessionId);
    state.failedOperations += 1;
  }

  /**
   * Evaluates role-based document access velocity against configurable limits.
   * If rate exceeds the role limit, flags rateLimitExceeded as a risk signal.
   */
  public checkRoleDocumentRate(sessionId: string, role: string): { 
    withinLimit: boolean; 
    currentRate: number; 
    maxAllowed: number 
  } {
    const state = this.getOrCreate(sessionId);
    const now = Date.now();
    state.requestTimestamps = state.requestTimestamps.filter(t => now - t <= 60000);
    const currentRate = state.requestTimestamps.length;
    const policy = getRoleDocumentPolicy(role);
    const withinLimit = currentRate <= policy.maxViewsPerMinute;

    if (!withinLimit) {
      state.rateLimitExceeded = true;
    }

    return {
      withinLimit,
      currentRate,
      maxAllowed: policy.maxViewsPerMinute
    };
  }

  public isRateLimitExceeded(sessionId: string): boolean {
    const state = this.sessions.get(sessionId);
    return state ? state.rateLimitExceeded : false;
  }

  public clearRateLimitExceeded(sessionId: string): void {
    const state = this.sessions.get(sessionId);
    if (state) state.rateLimitExceeded = false;
  }

  /**
   * Extracts the exact 6-dimensional feature vector matching the dataset schema.
   */
  public extractFeatures(session: ActiveSession): SessionBehavioralFeatures {
    const state = this.getOrCreate(session.id);
    const now = Date.now();

    state.requestTimestamps = state.requestTimestamps.filter(t => now - t <= 60000);
    const requestsPerMinute = state.requestTimestamps.length;

    // Login hour: current local hour (0-23) in Asia/Kolkata, or 23 if simulated night access
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
    const loginHour = session.simulatedNightAccess ? 23 : currentHour;

    // Session duration
    let durationMinutes = 1.0;
    try {
      if (session.loginTime) {
        const loginMs = new Date(session.loginTime).getTime();
        if (!isNaN(loginMs)) {
          durationMinutes = Math.max(0.5, Math.round(((now - loginMs) / 60000) * 10) / 10);
        }
      }
    } catch {
      durationMinutes = 1.0;
    }

    const failedOps = Math.max(state.failedOperations, session.failedActionCount || 0);

    return {
      login_hour: loginHour,
      records_viewed: state.recordsViewed,
      downloads_count: state.downloadsCount,
      requests_per_minute: requestsPerMinute,
      failed_operations: failedOps,
      session_duration_minutes: durationMinutes,
      ip_mismatch: session.simulatedIpMismatch ? 1 : 0,
      device_mismatch: session.simulatedDeviceMismatch ? 1 : 0
    };
  }

  public getSessionMetrics(sessionId: string) {
    const state = this.getOrCreate(sessionId);
    const now = Date.now();
    state.requestTimestamps = state.requestTimestamps.filter(t => now - t <= 60000);
    return {
      recordsViewed: state.recordsViewed,
      downloadsCount: state.downloadsCount,
      requestsPerMinute: state.requestTimestamps.length,
      failedOperations: state.failedOperations,
      rateLimitExceeded: state.rateLimitExceeded,
      distinctDocumentsCount: state.distinctDocumentIds.size
    };
  }

  public clearSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

export const sessionActivityTracker = new SessionActivityTracker();
export default sessionActivityTracker;
