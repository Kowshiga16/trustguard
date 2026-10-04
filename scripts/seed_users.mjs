import { MongoClient } from 'mongodb';
import bcrypt from 'bcrypt';

const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017';
const dbName = process.env.MONGO_DB_NAME || 'trustguard';

console.log('Seeding TrustGuard revenue department users...');
const client = new MongoClient(uri);
await client.connect();
const db = client.db(dbName);
const collection = db.collection('users');

const defaultPassword = 'Password@123';
const passwordHash = await bcrypt.hash(defaultPassword, 10);

const defaultUsers = [
  {
    id: 'u_admin_001',
    name: 'Admin Shrinivas',
    email: 'admin@trustguard.gov.in',
    passwordHash,
    roleName: 'System Administrator',
    phone: '9840011223',
    assignedJurisdiction: { district: 'Kancheepuram', taluk: 'Tambaram', villageId: 'v1' },
    registeredDevice: 'Admin-Workstation',
    properties: []
  },
  {
    id: 'u_tahsildar_001',
    name: 'Raj Kumar',
    email: 'raj.kumar@revenue.tn.gov.in',
    passwordHash,
    roleName: 'Tahsildar',
    phone: '9840122334',
    assignedJurisdiction: { district: 'Kancheepuram', taluk: 'Tambaram', villageId: 'v1' },
    registeredDevice: 'Tahsildar-Laptop',
    properties: []
  },
  {
    id: 'u_dt_001',
    name: 'Suresh Pillai',
    email: 'suresh.pillai@revenue.tn.gov.in',
    passwordHash,
    roleName: 'Deputy Tahsildar',
    phone: '9840233445',
    assignedJurisdiction: { district: 'Kancheepuram', taluk: 'Tambaram', villageId: 'v1' },
    registeredDevice: 'Deputy-Laptop',
    properties: []
  },
  {
    id: 'u_ri_001',
    name: 'Anitha Sundaram',
    email: 'anitha.ri@revenue.tn.gov.in',
    passwordHash,
    roleName: 'Revenue Inspector (RI)',
    phone: '9840344556',
    assignedJurisdiction: { district: 'Kancheepuram', taluk: 'Tambaram', villageId: 'v1' },
    registeredDevice: 'RI-Field-Tablet',
    properties: []
  },
  {
    id: 'u_vao_001',
    name: 'Balaji Rajan',
    email: 'balaji.vao@revenue.tn.gov.in',
    passwordHash,
    roleName: 'VAO / Village Officer',
    phone: '9840455667',
    assignedJurisdiction: { district: 'Kancheepuram', taluk: 'Tambaram', villageId: 'v1' },
    registeredDevice: 'VAO-Terminal-01',
    properties: []
  },
  {
    id: 'u_deo_001',
    name: 'Kavitha Selvam',
    email: 'kavitha.deo@revenue.tn.gov.in',
    passwordHash,
    roleName: 'Data Entry Operator',
    phone: '9840566778',
    assignedJurisdiction: { district: 'Kancheepuram', taluk: 'Tambaram', villageId: 'v1' },
    registeredDevice: 'DEO-Desktop-02',
    properties: []
  },
  {
    id: 'u_citizen_001',
    name: 'Ramesh Kumar',
    email: 'ramesh.citizen@gmail.com',
    passwordHash,
    roleName: 'Citizen / Land Owner',
    phone: '+91 98450 11223',
    assignedJurisdiction: { district: 'Kancheepuram', taluk: 'Tambaram', villageId: 'v1' },
    registeredDevice: 'Citizen-Mobile',
    properties: [
      {
        id: 'rec1',
        surveyNumber: '102/1',
        ownerName: 'Ramesh Kumar',
        ownerPhone: '+91 98450 11223',
        villageId: 'v1',
        villageName: 'Mudichur',
        area: '1.8 Acres',
        landType: 'Agricultural',
        status: 'Active',
        pattaNumber: 'Patta-102-001',
        chittaNumber: 'Chitta-102-001'
      }
    ]
  }
];

let insertedCount = 0;
let updatedCount = 0;

for (const user of defaultUsers) {
  const result = await collection.updateOne(
    { email: user.email },
    { $set: user },
    { upsert: true }
  );
  if (result.upsertedCount > 0) insertedCount++;
  else if (result.modifiedCount > 0) updatedCount++;
}

console.log(`Seeding complete: ${insertedCount} new user(s) created, ${updatedCount} user(s) updated.`);
console.log(`All users configured with password: "${defaultPassword}"`);

await client.close();
