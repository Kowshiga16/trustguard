/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Additive Session Activity Monitor
 * Tracks real-time user session metrics for Isolation Forest ML behavioral analysis:
 * 1. login_hour (time patterns)
 * 2. records_viewed (access frequency)
 * 3. downloads_count (document access rate)
 * 4. requests_per_minute (rolling velocity)
 * 5. failed_operations (failed access attempts)
 * 6. session_duration_minutes (historical duration)
 * 7. ip_mismatch (observed IP change)
 * 8. device_mismatch (observed device shift)
 * 9. distinct_documents_count (distinct documents inspected)
 * 10. document_sensitivity (highest classification inspected: 0=Public, 1=Restricted, 2=Confidential)
 */

import { ActiveSession } from "../src/types";

export interface SessionBehavioralFeatures {
  login_hour: number;
  records_viewed: number;
  downloads_count: number;
  requests_per_minute: number;
  failed_operations: number;
  session_duration_minutes: number;
  ip_mismatch: number;
  device_mismatch: number;
  distinct_documents_count?: number;
  document_sensitivity?: number;
}

interface InternalSessionState {
  recordsViewed: number;
  downloadsCount: number;
  requestTimestamps: number[];
  failedOperations: number;
  distinctDocumentIds: Set<string>;
  maxSensitivityLevel: number; // 0=Public, 1=Restricted, 2=Confidential
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
        distinctDocumentIds: new Set<string>(),
        maxSensitivityLevel: 0
      };
      this.sessions.set(sessionId, state);
    }
    return state;
  }

  public recordRequest(sessionId: string): void {
    const state = this.getOrCreate(sessionId);
    const now = Date.now();
    state.requestTimestamps.push(now);
    // Keep only timestamps from the last 60 seconds
    state.requestTimestamps = state.requestTimestamps.filter(t => now - t <= 60000);
  }

  public recordRecordView(sessionId: string, count: number = 1): void {
    const state = this.getOrCreate(sessionId);
    state.recordsViewed += count;
  }

  public recordDownload(sessionId: string, docId?: string, classification?: string): void {
    const state = this.getOrCreate(sessionId);
    state.downloadsCount += 1;
    if (docId) {
      state.distinctDocumentIds.add(docId);
    }
    if (classification) {
      const level = classification.toUpperCase() === "CONFIDENTIAL" ? 2 : (classification.toUpperCase() === "RESTRICTED" ? 1 : 0);
      if (level > state.maxSensitivityLevel) {
        state.maxSensitivityLevel = level;
      }
    }
  }

  public recordFailedOperation(sessionId: string): void {
    const state = this.getOrCreate(sessionId);
    state.failedOperations += 1;
  }

  public extractFeatures(session: ActiveSession): SessionBehavioralFeatures {
    const state = this.getOrCreate(session.id);
    const now = Date.now();

    // Clean up timestamps older than 60 seconds
    state.requestTimestamps = state.requestTimestamps.filter(t => now - t <= 60000);
    const requestsPerMinute = state.requestTimestamps.length;

    // Use hour 23 if night/off-hours access is simulated, otherwise real hour if within working hours or fallback to 12 PM
    const currentHour = new Date().getHours();
    const isWorkingHours = currentHour >= 10 && currentHour < 16;
    const defaultWorkingHour = isWorkingHours ? currentHour : (process.env.ENABLE_ORGANIC_OFFHOURS === "true" ? currentHour : 12);
    const loginHour = session.simulatedNightAccess ? 23 : defaultWorkingHour;

    // Session duration
    let durationMinutes = 1.0;
    try {
      if (session.loginTime) {
        const loginMs = new Date(session.loginTime).getTime();
        if (!isNaN(loginMs)) {
          durationMinutes = Math.max(0.1, Math.round(((now - loginMs) / 60000) * 10) / 10);
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
      device_mismatch: session.simulatedDeviceMismatch ? 1 : 0,
      distinct_documents_count: state.distinctDocumentIds.size,
      document_sensitivity: state.maxSensitivityLevel
    };
  }

  public getSessionMetrics(sessionId: string) {
    const state = this.getOrCreate(sessionId);
    return {
      recordsViewed: state.recordsViewed,
      downloadsCount: state.downloadsCount,
      requestsPerMinute: state.requestTimestamps.length,
      failedOperations: state.failedOperations,
      distinctDocumentsCount: state.distinctDocumentIds.size,
      maxSensitivityLevel: state.maxSensitivityLevel
    };
  }

  public clearSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

export const sessionActivityTracker = new SessionActivityTracker();
export default sessionActivityTracker;
