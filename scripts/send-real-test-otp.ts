import "dotenv/config";
import { emailService } from "../services/emailService";

async function main() {
  console.log("Sending live test OTP to spkaushik19@gmail.com...");
  const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
  const res = await emailService.sendOtpEmail({
    userName: "Raj Kumar (Tahsildar)",
    userEmail: "kowshiga931@gmail.com",
    userRole: "Tahsildar",
    otpCode,
    currentTrustScore: 52,
    roleThreshold: 70,
    expiresInMinutes: 10,
    reasons: [
      "Mid-Session IP Route Drift detected (-20)",
      "Unrecognized device fingerprint (-25)"
    ],
    triggerContext: "External Demo: Real-Time Zero Trust Step-Up Challenge",
    ipAddress: "10.244.52.8",
    device: "External Demo Workstation (Windows 11)"
  });

  console.log("Send Result:", res);
}

main().catch(console.error);
