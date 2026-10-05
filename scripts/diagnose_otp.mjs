import 'dotenv/config';

console.log("=======================================================================");
console.log("             TRUSTGUARD OTP SYSTEM DIAGNOSTIC TOOL                     ");
console.log("=======================================================================");

const brevoKey = process.env.BREVO_API_KEY?.trim();
const demoEmail = process.env.DEMO_OTP_EMAIL?.trim() || "kowshiga931@gmail.com";
const senderEmail = process.env.BREVO_SENDER_EMAIL?.trim() || "kowshiga931@gmail.com";
const smtpUser = process.env.SMTP_USER?.trim();
const nodeEnv = process.env.NODE_ENV || "development";

console.log(`\n1. ENVIRONMENT CONFIGURATION:`);
console.log(`   - NODE_ENV:             ${nodeEnv}`);
console.log(`   - DEMO_OTP_EMAIL:       ${demoEmail}`);
console.log(`   - BREVO_API_KEY:        ${brevoKey ? `[CONFIGURED: ${brevoKey.slice(0, 10)}...${brevoKey.slice(-4)}]` : '[NOT CONFIGURED - REQUIRED FOR RENDER]'}`);
console.log(`   - BREVO_SENDER_EMAIL:   ${senderEmail}`);
console.log(`   - SMTP_USER:            ${smtpUser || '[NOT SET]'}`);

console.log(`\n2. BREVO HTTPS API DIRECT TEST (Port 443):`);
if (!brevoKey) {
  console.log(`   ❌ BREVO_API_KEY is not set.`);
  console.log(`   👉 In Render Dashboard -> Environment -> Add BREVO_API_KEY.`);
} else {
  try {
    const accRes = await fetch("https://api.brevo.com/v3/account", {
      headers: { "api-key": brevoKey, "accept": "application/json" }
    });
    if (accRes.ok) {
      const data = await accRes.json();
      console.log(`   ✔ Brevo API Key: VALID & CONNECTED`);
      console.log(`   ✔ Registered Account Email: ${data.email}`);
      console.log(`   ✔ Account Name: ${data.firstName || ''} ${data.lastName || ''}`);
    } else {
      const err = await accRes.text();
      console.log(`   ❌ Brevo API Key Rejected (HTTP ${accRes.status}): ${err}`);
    }
  } catch (e) {
    console.log(`   ❌ Network error connecting to Brevo HTTPS API: ${e.message}`);
  }
}

console.log(`\n3. LIVE OTP GENERATION & DISPATCH TEST TO ${demoEmail}:`);
const testOtp = Math.floor(100000 + Math.random() * 900000).toString();
console.log(`   - Generated Secure 6-Digit Code: [${testOtp}]`);

if (brevoKey) {
  console.log(`   - Sending test email through Brevo HTTPS REST API...`);
  try {
    const sendRes = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "accept": "application/json",
        "api-key": brevoKey,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        sender: { name: "TrustGuard Security", email: senderEmail },
        to: [{ email: demoEmail, name: "Revenue Officer" }],
        subject: "TrustGuard Diagnostic: Test OTP Verification",
        htmlContent: `<p>Your diagnostic verification code is: <b>${testOtp}</b></p>`,
        textContent: `Your diagnostic verification code is: ${testOtp}`
      })
    });

    if (sendRes.ok) {
      const resJson = await sendRes.json();
      console.log(`   ✔ Email ACCEPTED by Brevo! MessageId: ${resJson.messageId}`);
      console.log(`   👉 Check your inbox (${demoEmail}) or Gmail Spam folder for the code!`);
    } else {
      const errText = await sendRes.text();
      console.log(`   ❌ Brevo rejected sending (HTTP ${sendRes.status}): ${errText}`);
    }
  } catch (err) {
    console.log(`   ❌ Network dispatch error: ${err.message}`);
  }
} else {
  console.log(`   ℹ Skipping live email dispatch because BREVO_API_KEY is not set.`);
}

console.log(`\n=======================================================================`);
console.log(`                          DIAGNOSTIC SUMMARY                           `);
console.log(`=======================================================================`);
console.log(`• On Deployed Render Link:`);
console.log(`  1. Ensure BREVO_API_KEY is set in Render Dashboard -> Environment.`);
console.log(`  2. Ensure DEMO_OTP_EMAIL is set to kowshiga931@gmail.com.`);
console.log(`  3. In the UI, click "Verify via OTP" in the top navigation bar.`);
console.log(`  4. If Trust Score <= 60 (Tahsildar threshold), OTP triggers automatically.`);
console.log(`=======================================================================\n`);
