import { MongoClient } from 'mongodb';

const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017';
const dbName = process.env.MONGO_DB_NAME || 'trustguard';

console.log('======================================================');
console.log('  TRUSTGUARD - MongoDB Health & Inspection Tool');
console.log('======================================================');
console.log(`Connecting to: ${uri}`);
console.log(`Database:      ${dbName}\n`);

try {
  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db(dbName);
  
  // Ping database
  await db.command({ ping: 1 });
  console.log('✔ MongoDB Connection: ACTIVE & HEALTHY\n');

  // List collections and document counts
  const collections = await db.listCollections().toArray();
  console.log(`Collections found in "${dbName}": ${collections.length}`);

  for (const col of collections) {
    const count = await db.collection(col.name).countDocuments();
    console.log(`  📁 ${col.name.padEnd(20)} : ${count} document(s)`);
  }

  // Display recent security alerts if any exist
  const alertsCol = db.collection('security_alerts');
  const alertCount = await alertsCol.countDocuments();
  if (alertCount > 0) {
    console.log('\n--- Recent Security Alerts (Latest 3) ---');
    const recentAlerts = await alertsCol.find().sort({ timestamp: -1 }).limit(3).toArray();
    for (const a of recentAlerts) {
      console.log(`  [${a.riskLevel}] ${a.userName} (${a.userRole})`);
      console.log(`    Score:   ${a.previousTrustScore} -> ${a.currentTrustScore}`);
      console.log(`    Action:  ${a.policyAction}`);
      console.log(`    Email:   ${a.emailAlertSent ? 'Sent to ' + a.emailRecipient : 'Not Sent'}`);
      console.log(`    Time:    ${a.timestamp}\n`);
    }
  }

  // Display recent audit logs
  const auditsCol = db.collection('audit_logs');
  const auditCount = await auditsCol.countDocuments();
  if (auditCount > 0) {
    console.log('--- Recent Audit Logs (Latest 3) ---');
    const recentAudits = await auditsCol.find().sort({ timestamp: -1 }).limit(3).toArray();
    for (const au of recentAudits) {
      console.log(`  [${au.decision}] ${au.userName} - ${au.actionPerformed} (Score: ${au.trustScoreAtAction})`);
    }
  }

  await client.close();
  console.log('\n======================================================');
} catch (error) {
  console.error('✖ MongoDB Connection Error:', error.message);
}
