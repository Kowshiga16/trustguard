import "dotenv/config";
import { emailService } from "../services/emailService";

async function main() {
  console.log("Testing Gmail SMTP connection...");
  const res = await emailService.verifyConnection();
  console.log("Result:", res);
  if (res.healthy) {
    console.log("SUCCESS: Gmail connection established!");
  } else {
    console.log("FAILURE: Could not verify Gmail credentials:", res.message);
  }
}

main().catch(console.error);
