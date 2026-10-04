/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Email Service
 * Production-ready, resilient NodeMailer integration for automated
 * Zero Trust security alert notifications.
 */

import nodemailer from "nodemailer";
import type { Transporter } from "nodemailer";
import { trustConfig, RiskLevel } from "./trustConfig";

export interface TrustAlertEmailData {
  userName: string;
  userEmail?: string;
  userRole: string;
  previousTrustScore: number;
  currentTrustScore: number;
  riskLevel: string;
  reasons: string[];
  ipAddress: string;
  location: string;
  device: string;
  timestamp: string;
  policyDecision: string;
  requestResource?: string;
  recipientEmail?: string;
}

export interface OtpEmailData {
  userName: string;
  userEmail: string;
  userRole: string;
  otpCode: string;
  currentTrustScore: number;
  roleThreshold: number;
  expiresInMinutes?: number;
  reasons?: string[];
  triggerContext?: string;
  ipAddress?: string;
  location?: string;
  device?: string;
  timestamp?: string;
}

export interface EmailSendResult {
  success: boolean;
  messageId?: string;
  error?: string;
  simulated?: boolean;
  otpCode?: string;
}

class EmailService {
  private transporter: Transporter | null = null;
  private isConfigured: boolean = false;

  constructor() {
    this.initTransporter();
  }

  /**
   * Initializes the NodeMailer SMTP transporter using environment variables.
   * Never hardcodes credentials or exposes secrets.
   */
  private initTransporter(): void {
    const { host, port, secure, user, pass, enabled } = trustConfig.smtp;

    if (!enabled) {
      console.log("[EmailService] Email alerts are disabled via ENABLE_EMAIL_ALERTS=false.");
      this.isConfigured = false;
      return;
    }

    if (!host || !user || !pass) {
      console.warn(
        "[EmailService] SMTP credentials not fully configured in environment (SMTP_HOST, SMTP_USER, SMTP_PASS).\n" +
        "Operating in DEVELOPMENT MOCK mode: Security alerts will be logged to console and audit trail."
      );
      this.isConfigured = false;
      return;
    }

    try {
      const isGmail = host.toLowerCase().includes("gmail") || user.toLowerCase().endsWith("@gmail.com");
      const cleanPass = pass.trim().replace(/\s+/g, "");

      this.transporter = isGmail
        ? nodemailer.createTransport({
            service: "gmail",
            auth: {
              user: user.trim(),
              pass: cleanPass,
            },
          })
        : nodemailer.createTransport({
            host: host.trim(),
            port,
            secure,
            auth: {
              user: user.trim(),
              pass: cleanPass,
            },
            tls: {
              rejectUnauthorized: false // Support corporate/internal gateways
            },
            pool: true,
            maxConnections: 5,
            maxMessages: 100,
          });

      this.isConfigured = true;
      console.log(`[EmailService] NodeMailer ${isGmail ? "Gmail" : "SMTP"} Transporter initialized successfully (${user.trim()}).`);
    } catch (err: any) {
      console.error("[EmailService] Failed to initialize SMTP Transporter:", err?.message || err);
      this.isConfigured = false;
      this.transporter = null;
    }
  }

  /**
   * Verifies the SMTP connection health.
   */
  public async verifyConnection(): Promise<{ healthy: boolean; message: string }> {
    if (!this.isConfigured || !this.transporter) {
      return {
        healthy: false,
        message: "SMTP not configured. Using development simulated email logger."
      };
    }

    try {
      await this.transporter.verify();
      return { healthy: true, message: "SMTP Transporter verified and ready to deliver alerts." };
    } catch (err: any) {
      return { healthy: false, message: `SMTP connection verification failed: ${err.message}` };
    }
  }

  /**
   * Generates a clean, accessible plain-text alert body.
   */
  private generatePlainTextBody(data: TrustAlertEmailData): string {
    const scoreDiff = data.currentTrustScore - data.previousTrustScore;
    const diffSign = scoreDiff > 0 ? `+${scoreDiff}` : `${scoreDiff}`;
    const reasonsList = data.reasons.length > 0 
      ? data.reasons.map(r => `  * ${r}`).join("\n")
      : "  * Continuous evaluation anomaly threshold reached";

    return `
======================================================================
TRUSTGUARD ZERO TRUST SECURITY ALERT: SUSPICIOUS ACTIVITY DETECTED
======================================================================

An abnormal security event has triggered dynamic trust score degradation
for a government land records access session.

----------------------------------------------------------------------
USER & ACCESS CONTEXT
----------------------------------------------------------------------
User Name:             ${data.userName}
User Email:            ${data.userEmail || "N/A"}
User Role:             ${data.userRole}
Previous Trust Score:  ${data.previousTrustScore} / 100
Current Trust Score:   ${data.currentTrustScore} / 100 (${diffSign} points)
Risk Level:            ${data.riskLevel}

----------------------------------------------------------------------
REASONS FOR TRUST SCORE REDUCTION
----------------------------------------------------------------------
${reasonsList}

----------------------------------------------------------------------
SESSION FORENSIC SIGNALS
----------------------------------------------------------------------
IP Address:            ${data.ipAddress}
Approximate Location:  ${data.location}
Device Fingerprint:    ${data.device}
Resource Accessed:     ${data.requestResource || "Continuous Evaluation Engine"}
Timestamp:             ${data.timestamp}

----------------------------------------------------------------------
POLICY DECISION ENGINE RESPONSE
----------------------------------------------------------------------
Action Enforced:       ${data.policyDecision}

----------------------------------------------------------------------
Security Notice:
This is an automated Zero Trust enforcement notification generated by
TrustGuard for the Land Records Management System.
Do not reply to this email. For security escalations, contact the
State Revenue Security Operation Center (SOC).
======================================================================
`.trim();
  }

  /**
   * Generates a modern, responsive HTML security alert email.
   */
  private generateHtmlBody(data: TrustAlertEmailData): string {
    const scoreDiff = data.currentTrustScore - data.previousTrustScore;
    const diffText = scoreDiff > 0 ? `+${scoreDiff}` : `${scoreDiff}`;

    // Risk level badge color
    let badgeBg = "#f59e0b"; // Suspicious Amber
    let badgeText = "#ffffff";
    let accentBorder = "#d97706";

    if (data.riskLevel === RiskLevel.CRITICAL || data.riskLevel.includes("CRITICAL")) {
      badgeBg = "#dc2626"; // Crimson Red
      accentBorder = "#b91c1c";
    } else if (data.riskLevel === RiskLevel.HIGH_RISK || data.riskLevel.includes("HIGH")) {
      badgeBg = "#ea580c"; // Deep Orange
      accentBorder = "#c2410c";
    }

    const reasonsHtml = data.reasons.length > 0
      ? data.reasons.map(r => `
          <li style="margin-bottom: 6px; color: #334155; font-size: 13px; line-height: 1.5;">
            <strong>${escapeHtml(r)}</strong>
          </li>
        `).join("")
      : `<li style="color: #64748b; font-size: 13px;">Suspicious anomaly detected during continuous policy evaluation.</li>`;

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TrustGuard Security Alert</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #0f172a; padding: 32px 16px;">
    <tr>
      <td align="center">
        <!-- Main Card -->
        <table role="presentation" width="100%" style="max-width: 620px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4); border-top: 5px solid ${accentBorder};" cellspacing="0" cellpadding="0" border="0">
          
          <!-- Header Banner -->
          <tr>
            <td style="background-color: #1e293b; padding: 24px 30px; text-align: left;">
              <table width="100%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td>
                    <div style="font-size: 10px; font-weight: 800; letter-spacing: 2px; color: #38bdf8; text-transform: uppercase;">
                      TRUSTGUARD ZERO TRUST ACCESS CONTROL
                    </div>
                    <div style="font-size: 20px; font-weight: 800; color: #ffffff; margin-top: 4px;">
                      Security Alert: Suspicious Activity Detected
                    </div>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 2px;">
                      Department of Land Records & Mutation Management
                    </div>
                  </td>
                  <td align="right" valign="top">
                    <span style="display: inline-block; background-color: ${badgeBg}; color: ${badgeText}; padding: 6px 14px; border-radius: 9999px; font-size: 11px; font-weight: 800; letter-spacing: 1px; text-transform: uppercase;">
                      ${escapeHtml(data.riskLevel)}
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Content Body -->
          <tr>
            <td style="padding: 28px 30px; background-color: #ffffff;">
              <p style="margin: 0 0 18px 0; font-size: 14px; line-height: 1.6; color: #334155;">
                The <strong>Dynamic Trust Engine</strong> has detected anomalous session behavior that crossed the security threshold. Access privileges have been automatically evaluated and adjusted by the <strong>Policy Decision Engine</strong>.
              </p>

              <!-- Trust Score Change Box -->
              <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 22px;">
                <tr>
                  <td style="padding: 16px 20px; width: 50%; border-right: 1px solid #e2e8f0;">
                    <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px;">Previous Trust Score</div>
                    <div style="font-size: 24px; font-weight: 800; color: #0f172a; margin-top: 4px;">
                      ${data.previousTrustScore} <span style="font-size: 13px; color: #64748b; font-weight: 500;">/ 100</span>
                    </div>
                  </td>
                  <td style="padding: 16px 20px; width: 50%;">
                    <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px;">Current Trust Score</div>
                    <div style="font-size: 24px; font-weight: 800; color: ${accentBorder}; margin-top: 4px;">
                      ${data.currentTrustScore} <span style="font-size: 13px; color: #64748b; font-weight: 500;">/ 100</span>
                      <span style="font-size: 12px; font-weight: 700; padding: 2px 6px; border-radius: 4px; background-color: #fee2e2; color: #b91c1c; margin-left: 6px;">
                        ${diffText}
                      </span>
                    </div>
                  </td>
                </tr>
              </table>

              <!-- User Information Table -->
              <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #0f172a; margin-bottom: 8px;">
                User Profile
              </div>
              <table width="100%" cellspacing="0" cellpadding="8" border="0" style="font-size: 13px; color: #334155; margin-bottom: 22px; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #f1f5f9;">
                  <td style="width: 35%; color: #64748b; font-weight: 600;">User Name</td>
                  <td style="font-weight: 700; color: #0f172a;">${escapeHtml(data.userName)}</td>
                </tr>
                <tr style="border-bottom: 1px solid #f1f5f9;">
                  <td style="color: #64748b; font-weight: 600;">User Email</td>
                  <td>${escapeHtml(data.userEmail || "Not Provided")}</td>
                </tr>
                <tr style="border-bottom: 1px solid #f1f5f9;">
                  <td style="color: #64748b; font-weight: 600;">Assigned Role</td>
                  <td><span style="background-color: #e0e7ff; color: #3730a3; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 12px;">${escapeHtml(data.userRole)}</span></td>
                </tr>
              </table>

              <!-- Detected Reasons Box -->
              <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #0f172a; margin-bottom: 8px;">
                Reasons for Trust Degradation
              </div>
              <div style="background-color: #fffbeb; border: 1px solid #fef3c7; border-left: 4px solid #f59e0b; padding: 14px 16px; border-radius: 6px; margin-bottom: 22px;">
                <ul style="margin: 0; padding-left: 20px;">
                  ${reasonsHtml}
                </ul>
              </div>

              <!-- Forensic Context Grid -->
              <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #0f172a; margin-bottom: 8px;">
                Session Forensics
              </div>
              <table width="100%" cellspacing="0" cellpadding="8" border="0" style="font-size: 13px; color: #334155; margin-bottom: 22px; border-collapse: collapse; background-color: #f8fafc; border-radius: 6px;">
                <tr style="border-bottom: 1px solid #e2e8f0;">
                  <td style="width: 35%; color: #64748b; font-weight: 600;">IP Address</td>
                  <td style="font-family: monospace; font-weight: 700; color: #0f172a;">${escapeHtml(data.ipAddress)}</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                  <td style="color: #64748b; font-weight: 600;">Location</td>
                  <td>${escapeHtml(data.location)}</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                  <td style="color: #64748b; font-weight: 600;">Device Context</td>
                  <td style="font-family: monospace; font-size: 12px;">${escapeHtml(data.device)}</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                  <td style="color: #64748b; font-weight: 600;">Resource / Action</td>
                  <td style="font-family: monospace; font-size: 12px;">${escapeHtml(data.requestResource || "/api/continuous-eval")}</td>
                </tr>
                <tr>
                  <td style="color: #64748b; font-weight: 600;">Timestamp</td>
                  <td style="font-size: 12px; color: #475569;">${escapeHtml(data.timestamp)}</td>
                </tr>
              </table>

              <!-- Policy Decision Enforced Banner -->
              <div style="background-color: #f1f5f9; border: 1px solid #cbd5e1; border-left: 4px solid #3b82f6; padding: 14px 18px; border-radius: 6px;">
                <div style="font-size: 11px; font-weight: 800; color: #1e3a8a; text-transform: uppercase; letter-spacing: 0.5px;">
                  Policy Decision Engine Action Enforced
                </div>
                <div style="font-size: 15px; font-weight: 700; color: #0f172a; margin-top: 4px;">
                  ${escapeHtml(data.policyDecision)}
                </div>
              </div>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #f8fafc; padding: 20px 30px; text-align: center; border-top: 1px solid #e2e8f0;">
              <div style="font-size: 11px; color: #64748b; line-height: 1.5;">
                This is an automated zero-trust security dispatch. All activities are recorded in the immutable audit ledger.<br>
                <strong>TrustGuard Access Control System</strong> &bull; Secured Land Records Registry
              </div>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`.trim();
  }

  /**
   * Reusable function to dispatch an alert email using NodeMailer.
   * Completely safe, non-blocking, and never crashes on failure.
   */
  public async sendTrustScoreAlert(alertData: TrustAlertEmailData): Promise<EmailSendResult> {
    const recipient = resolveActualRecipient(alertData.recipientEmail || trustConfig.smtp.securityAlertEmail);
    const subject = `TrustGuard Security Alert: Suspicious Activity Detected [${alertData.riskLevel}]`;

    // 1. If email alerts disabled
    if (!trustConfig.smtp.enabled) {
      console.log(`[EmailService] Email alert skipped (ENABLE_EMAIL_ALERTS is false). Target: ${recipient}`);
      return { success: true, simulated: true };
    }

    // 2. If SMTP is not fully configured, log to console in dev mode
    if (!this.isConfigured || !this.transporter) {
      console.log("\n=======================================================================");
      console.log("  [TrustGuard NodeMailer MOCK SENDER] - Security Alert Notification");
      console.log(`  To:      ${recipient}`);
      console.log(`  Subject: ${subject}`);
      console.log(`  User:    ${alertData.userName} (${alertData.userRole})`);
      console.log(`  Score:   ${alertData.previousTrustScore} -> ${alertData.currentTrustScore} [${alertData.riskLevel}]`);
      console.log(`  Action:  ${alertData.policyDecision}`);
      console.log(`  Reasons: ${alertData.reasons.join(", ") || "None specified"}`);
      console.log("=======================================================================\n");
      return {
        success: true,
        simulated: true,
        messageId: `sim_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`
      };
    }

    // 3. Send real email via SMTP
    try {
      const textContent = this.generatePlainTextBody(alertData);
      const htmlContent = this.generateHtmlBody(alertData);

      const info = await this.transporter.sendMail({
        from: getSenderAddress(),
        to: recipient,
        subject,
        text: textContent,
        html: htmlContent,
        priority: alertData.riskLevel === RiskLevel.CRITICAL ? "high" : "normal",
        headers: {
          "X-TrustGuard-Alert-Level": alertData.riskLevel,
          "X-TrustGuard-User": alertData.userName,
          "X-TrustGuard-Current-Score": String(alertData.currentTrustScore)
        }
      });

      console.log(`[EmailService] Alert email successfully sent to ${recipient}. MessageId: ${info.messageId}`);
      return {
        success: true,
        messageId: info.messageId,
        simulated: false
      };
    } catch (err: any) {
      // Never crash or expose passwords
      console.error(`[EmailService] Failed to send alert email to ${recipient}:`, err?.message || err);
      return {
        success: false,
        error: err?.message || "Unknown SMTP delivery error",
        simulated: false
      };
    }
  }

  /**
   * Safe asynchronous fire-and-forget alert dispatch.
   * Ensures normal API responses are not blocked by email sending latency.
   */
  public sendTrustScoreAlertAsync(
    alertData: TrustAlertEmailData, 
    onComplete?: (result: EmailSendResult) => void
  ): void {
    setImmediate(async () => {
      try {
        const result = await this.sendTrustScoreAlert(alertData);
        if (onComplete) onComplete(result);
      } catch (err) {
        console.error("[EmailService] Unexpected error in async email dispatch:", err);
      }
    });
  }

  /**
   * Generates a plain-text body for the OTP verification email.
   */
  private generateOtpPlainTextBody(data: OtpEmailData): string {
    const expiry = data.expiresInMinutes || 10;
    const reasonsList = data.reasons && data.reasons.length > 0
      ? data.reasons.map(r => `  * ${r}`).join("\n")
      : "  * Continuous evaluation: Session trust score dropped below role operational threshold";

    return `
======================================================================
TRUSTGUARD STEP-UP AUTHENTICATION: IDENTITY VERIFICATION OTP
======================================================================

An action or security anomaly has triggered a Zero-Trust Step-Up
authentication challenge for your land records administration session.

----------------------------------------------------------------------
OFFICER & ROLE DETAILS
----------------------------------------------------------------------
Officer Name:         ${data.userName}
Official Email:       ${data.userEmail}
Designated Role:      ${data.userRole}
Current Trust Score:  ${data.currentTrustScore} / 100
Role OTP Threshold:   ${data.roleThreshold} / 100
Trigger Event:        ${data.triggerContext || "Dynamic Trust Degradation (Threat Simulation / Policy Evaluation)"}

----------------------------------------------------------------------
YOUR ONE-TIME STEP-UP VERIFICATION CODE:
----------------------------------------------------------------------
                     >>>  ${data.otpCode}  <<<
----------------------------------------------------------------------
* This code expires in ${expiry} minutes.
* Enter this code in the TrustGuard verification prompt to restore session access.

----------------------------------------------------------------------
SECURITY SIGNALS DETECTED
----------------------------------------------------------------------
${reasonsList}
IP Address:           ${data.ipAddress || "Active Session Route"}
Device Fingerprint:   ${data.device || "Monitored Client"}
Timestamp:            ${data.timestamp || new Date().toISOString()}

Security Notice:
Do not disclose this verification code to anyone. Government revenue
officers will never solicit your one-time password.
======================================================================
`.trim();
  }

  /**
   * Generates a high-security responsive HTML email for the OTP code.
   */
  private generateOtpHtmlBody(data: OtpEmailData): string {
    const expiry = data.expiresInMinutes || 10;
    const reasonsList = data.reasons && data.reasons.length > 0
      ? data.reasons.map(r => `
          <li style="margin-bottom: 5px; color: #334155; font-size: 13px;">
            <strong>${escapeHtml(r)}</strong>
          </li>
        `).join("")
      : `<li style="color: #64748b; font-size: 13px;">Trust score (${data.currentTrustScore}/100) dropped below role threshold (${data.roleThreshold}/100).</li>`;

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>TrustGuard Step-Up OTP Verification</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; margin: 0; padding: 24px; color: #1e293b;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="600" border="0" cellspacing="0" cellpadding="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1); border: 1px solid #e2e8f0;">
          
          <!-- Government Header -->
          <tr>
            <td style="background-color: #0f172a; padding: 24px 30px; text-align: left; border-bottom: 3px solid #4f46e5;">
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <span style="font-size: 11px; font-weight: 800; letter-spacing: 1.5px; text-transform: uppercase; color: #818cf8; display: block; margin-bottom: 4px;">
                      TrustGuard Zero Trust Access Control
                    </span>
                    <span style="font-size: 18px; font-weight: 800; color: #ffffff; letter-spacing: -0.5px;">
                      Step-Up Identity Verification (OTP)
                    </span>
                  </td>
                  <td align="right">
                    <span style="display: inline-block; padding: 5px 12px; border-radius: 9999px; font-size: 11px; font-weight: 800; text-transform: uppercase; background-color: #312e81; color: #c7d2fe; border: 1px solid #4338ca;">
                      ${escapeHtml(data.userRole)}
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Body -->
          <tr>
            <td style="padding: 30px;">
              <p style="font-size: 14px; line-height: 1.6; color: #475569; margin: 0 0 20px 0;">
                Dear <strong>${escapeHtml(data.userName)}</strong>,
              </p>
              <p style="font-size: 14px; line-height: 1.6; color: #475569; margin: 0 0 22px 0;">
                Your session trust score has degraded to <strong>${data.currentTrustScore}/100</strong>, which is below the required operating baseline of <strong>${data.roleThreshold}/100</strong> for the <strong>${escapeHtml(data.userRole)}</strong> role.
                To confirm your identity and unlock revenue actions, please enter this one-time passcode:
              </p>

              <!-- Prominent OTP Code Box -->
              <div style="background-color: #eef2ff; border: 2px dashed #6366f1; border-radius: 10px; padding: 22px; text-align: center; margin-bottom: 24px;">
                <span style="display: block; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; color: #4338ca; margin-bottom: 8px;">
                  Your 6-Digit One-Time Password
                </span>
                <span style="display: block; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 36px; font-weight: 900; letter-spacing: 12px; color: #1e1b4b; text-indent: 12px;">
                  ${escapeHtml(data.otpCode)}
                </span>
                <span style="display: block; font-size: 12px; font-weight: 600; color: #6366f1; margin-top: 10px;">
                  ⏱️ Valid for ${expiry} minutes &bull; Single-use only
                </span>
              </div>

              <!-- Context Details -->
              <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #0f172a; margin-bottom: 8px;">
                Verification Trigger Details
              </div>
              <table width="100%" cellspacing="0" cellpadding="8" border="0" style="font-size: 13px; color: #334155; margin-bottom: 22px; border-collapse: collapse; background-color: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0;">
                <tr style="border-bottom: 1px solid #e2e8f0;">
                  <td style="width: 35%; color: #64748b; font-weight: 600;">Trigger Context</td>
                  <td style="font-weight: 700; color: #0f172a;">${escapeHtml(data.triggerContext || "Dynamic Anomaly / Threat Simulation")}</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                  <td style="color: #64748b; font-weight: 600;">Trust Degradation</td>
                  <td>Current: <strong style="color: #d97706;">${data.currentTrustScore}</strong> / Role Baseline: <strong>${data.roleThreshold}</strong></td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                  <td style="color: #64748b; font-weight: 600;">Client IP</td>
                  <td style="font-family: monospace;">${escapeHtml(data.ipAddress || "127.0.0.1")}</td>
                </tr>
                <tr>
                  <td style="color: #64748b; font-weight: 600;">Timestamp</td>
                  <td style="font-size: 12px; color: #475569;">${escapeHtml(data.timestamp || new Date().toISOString())}</td>
                </tr>
              </table>

              <!-- Detected Reasons -->
              <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #0f172a; margin-bottom: 8px;">
                Security Anomalies Flagged
              </div>
              <div style="background-color: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 4px; margin-bottom: 22px;">
                <ul style="margin: 0; padding-left: 18px;">
                  ${reasonsList}
                </ul>
              </div>

              <div style="font-size: 11px; color: #64748b; line-height: 1.5; background-color: #f1f5f9; padding: 12px; border-radius: 6px;">
                <strong>Security Notice:</strong> If you did not trigger this action, your credentials or session may be compromised. Immediately notify your Revenue District Administrator.
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #f8fafc; padding: 18px 30px; text-align: center; border-top: 1px solid #e2e8f0;">
              <div style="font-size: 11px; color: #64748b; line-height: 1.4;">
                TrustGuard Zero Trust Access Control &bull; Government Land Records Administration<br>
                Automated Identity Assurance Engine
              </div>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`.trim();
  }

  /**
   * Sends a Step-Up Authentication OTP email to the user using NodeMailer.
   * Completely resilient: safely logs in development mock mode and catches any transport errors.
   */
  public async sendOtpEmail(otpData: OtpEmailData): Promise<EmailSendResult & { otpCode?: string }> {
    const recipient = resolveActualRecipient(otpData.userEmail);
    const subject = `TrustGuard Security: Step-Up Identity Verification OTP [${otpData.otpCode}]`;
    const expiry = otpData.expiresInMinutes || 10;

    // 1. If email alerts disabled
    if (!trustConfig.smtp.enabled) {
      console.log(`[EmailService] OTP email skipped (ENABLE_EMAIL_ALERTS is false). Target: ${recipient}`);
      return { success: true, simulated: true, otpCode: otpData.otpCode };
    }

    // 2. If SMTP is not fully configured, log to console in dev mode
    if (!this.isConfigured || !this.transporter) {
      console.log("\n=======================================================================");
      console.log("  [TrustGuard NodeMailer MOCK SENDER] - Step-Up Verification OTP");
      console.log(`  To:       ${recipient}`);
      console.log(`  Subject:  ${subject}`);
      console.log(`  Officer:  ${otpData.userName} (${otpData.userRole})`);
      console.log(`  OTP CODE: >>> ${otpData.otpCode} <<< (Valid for ${expiry} minutes)`);
      console.log(`  Score:    ${otpData.currentTrustScore} / Role Low-Trust Threshold: ${otpData.roleThreshold}`);
      console.log(`  Context:  ${otpData.triggerContext || "Dynamic Anomaly / Threat Simulation"}`);
      if (otpData.reasons && otpData.reasons.length > 0) {
        console.log(`  Reasons:  ${otpData.reasons.join(", ")}`);
      }
      console.log("=======================================================================\n");

      return {
        success: true,
        simulated: true,
        otpCode: otpData.otpCode,
        messageId: `otp_sim_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`
      };
    }

    // 3. Send real email via SMTP
    try {
      const textContent = this.generateOtpPlainTextBody(otpData);
      const htmlContent = this.generateOtpHtmlBody(otpData);

      const info = await this.transporter.sendMail({
        from: getSenderAddress(),
        to: recipient,
        subject,
        text: textContent,
        html: htmlContent,
        priority: "high",
        headers: {
          "X-TrustGuard-Challenge": "STEP_UP_OTP",
          "X-TrustGuard-User": otpData.userName,
          "X-TrustGuard-Role": otpData.userRole,
          "X-TrustGuard-Score": String(otpData.currentTrustScore)
        }
      });

      console.log(`[EmailService] Step-Up OTP email successfully sent to ${recipient}. MessageId: ${info.messageId}`);
      return {
        success: true,
        simulated: false,
        otpCode: otpData.otpCode,
        messageId: info.messageId
      };
    } catch (err: any) {
      console.error(`[EmailService] Failed to send OTP email to ${recipient}:`, err?.message || err);
      return {
        success: false,
        error: err?.message || "Unknown SMTP delivery error",
        simulated: false,
        otpCode: otpData.otpCode
      };
    }
  }

  /**
   * Safe asynchronous fire-and-forget OTP email dispatch.
   */
  public sendOtpEmailAsync(
    otpData: OtpEmailData,
    onComplete?: (result: EmailSendResult) => void
  ): void {
    setImmediate(async () => {
      try {
        const result = await this.sendOtpEmail(otpData);
        if (onComplete) onComplete(result);
      } catch (err) {
        console.error("[EmailService] Unexpected error in async OTP email dispatch:", err);
      }
    });
  }
}

function escapeHtml(str: string): string {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function resolveActualRecipient(preferredEmail?: string): string {
  const override = process.env.OVERRIDE_RECIPIENT_EMAIL?.trim() || "kowshiga931@gmail.com";
  if (override && override.includes("@")) return override;

  if (
    preferredEmail && 
    !preferredEmail.includes("@revenue.tn.gov.in") && 
    !preferredEmail.includes("@trustguard.gov.in") && 
    !preferredEmail.includes("@registered.local")
  ) {
    return preferredEmail;
  }

  // If the target is a dummy revenue address, route it to the configured real Gmail inbox!
  if (trustConfig.smtp.securityAlertEmail && !trustConfig.smtp.securityAlertEmail.includes("@trustguard.gov.in")) {
    return trustConfig.smtp.securityAlertEmail;
  }
  if (trustConfig.smtp.user && trustConfig.smtp.user.includes("@")) {
    return trustConfig.smtp.user;
  }

  return preferredEmail || "officer@revenue.tn.gov.in";
}

export function getSenderAddress(): string {
  if (trustConfig.smtp.from && !trustConfig.smtp.from.includes("@trustguard.gov.in")) {
    return trustConfig.smtp.from;
  }
  if (trustConfig.smtp.user && trustConfig.smtp.user.includes("@")) {
    return `"TrustGuard Security Engine" <${trustConfig.smtp.user}>`;
  }
  return trustConfig.smtp.from;
}

export const emailService = new EmailService();
export default emailService;
