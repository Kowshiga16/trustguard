import { MongoClient } from 'mongodb';
import 'dotenv/config';

const uri = process.argv[2] || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/trustguard';
const dbName = process.env.MONGO_DB_NAME || 'trustguard';

const DEFAULT_PASSWORD_HASH = '$2b$10$JYbn94UeUTp7EGNdpHCLYucb99z.bn3NDklzw.Si8BoHrupEaW4yG'; // Password@123

const SEED_USERS = [
  {
    id: "u_admin_001",
    name: "Admin Shrinivas",
    email: "admin@trustguard.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: "System Administrator",
    phone: "9840011223",
    assignedJurisdiction: { district: "Kancheepuram", taluk: "Tambaram", villageId: "v1" },
    registeredDevice: "Admin-Workstation",
    properties: [],
    status: "Active"
  },
  {
    id: "u_tahsildar_001",
    name: "Raj Kumar",
    email: "raj.kumar@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: "Tahsildar",
    phone: "9840122334",
    assignedJurisdiction: { district: "Kancheepuram", taluk: "Tambaram", villageId: "v1" },
    registeredDevice: "Tahsildar-Laptop",
    properties: [],
    status: "Active"
  },
  {
    id: "u_dt_001",
    name: "Suresh Pillai",
    email: "suresh.pillai@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: "Deputy Tahsildar",
    phone: "9840233445",
    assignedJurisdiction: { district: "Kancheepuram", taluk: "Tambaram", villageId: "v1" },
    registeredDevice: "Deputy-Laptop",
    properties: [],
    status: "Active"
  },
  {
    id: "u_ri_001",
    name: "Anitha Sundaram",
    email: "anitha.ri@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: "Revenue Inspector (RI)",
    phone: "9840344556",
    assignedJurisdiction: { district: "Kancheepuram", taluk: "Tambaram", villageId: "v1" },
    registeredDevice: "RI-Field-Tablet",
    properties: [],
    status: "Active"
  },
  {
    id: "u_vao_001",
    name: "Balaji Rajan",
    email: "balaji.vao@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: "VAO / Village Officer",
    phone: "9840455667",
    assignedJurisdiction: { district: "Kancheepuram", taluk: "Tambaram", villageId: "v1" },
    registeredDevice: "VAO-Terminal-01",
    properties: [],
    status: "Active"
  },
  {
    id: "u_deo_001",
    name: "Kavitha Selvam",
    email: "kavitha.deo@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: "Data Entry Operator",
    phone: "9840566778",
    assignedJurisdiction: { district: "Kancheepuram", taluk: "Tambaram", villageId: "v1" },
    registeredDevice: "DEO-Desktop-02",
    properties: [],
    status: "Active"
  },
  {
    id: "u_citizen_001",
    name: "Ramesh Kumar",
    email: "ramesh.citizen@gmail.com",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: "Citizen / Land Owner",
    phone: "+91 98450 11223",
    assignedJurisdiction: { district: "Kancheepuram", taluk: "Tambaram", villageId: "v1" },
    registeredDevice: "Citizen-Mobile",
    properties: [
      {
        id: "rec1",
        surveyNumber: "102/1",
        ownerName: "Ramesh Kumar",
        ownerPhone: "+91 98450 11223",
        villageId: "v1",
        villageName: "Mudichur",
        area: "1.8 Acres",
        landType: "Agricultural",
        status: "Active",
        pattaNumber: "Patta-102-001",
        chittaNumber: "Chitta-102-001"
      }
    ],
    status: "Active"
  },
  {
    id: "u_officer_test",
    name: "Test Officer",
    email: "officer.test@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: "VAO / Village Officer",
    phone: "9998887776",
    assignedJurisdiction: { district: "Kancheepuram", taluk: "Tambaram", villageId: "v1" },
    registeredDevice: "Test-Device",
    properties: [],
    status: "Active"
  },
  {
    id: "u_tahsildar_test",
    name: "Test Tahsildar",
    email: "tahsildar@test.local",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: "Tahsildar",
    phone: "997688045",
    assignedJurisdiction: { district: "Kancheepuram", taluk: "Tambaram", villageId: "v1" },
    registeredDevice: "Tahsildar-Laptop",
    properties: [],
    status: "Active"
  }
];

const SEED_VILLAGES = [
  { id: "v1", name: "Mudichur", taluk: "Tambaram", district: "Kancheepuram" },
  { id: "v2", name: "Manapakkam", taluk: "Tambaram", district: "Kancheepuram" },
  { id: "v3", name: "Pennalur", taluk: "Sriperumbudur", district: "Kancheepuram" },
  { id: "v4", name: "Pillaipakkam", taluk: "Sriperumbudur", district: "Kancheepuram" },
  { id: "v5", name: "Gudalur", taluk: "Coimbatore South", district: "Coimbatore" }
];

const SEED_LAND_RECORDS = [
  { 
    id: "rec1", 
    surveyNumber: "102/1", 
    ownerName: "Ramesh Kumar", 
    ownerPhone: "+91 98450 11223", 
    villageId: "v1", 
    villageName: "Mudichur", 
    district: "Kancheepuram",
    taluk: "Tambaram",
    area: "1.8 Acres", 
    landType: "Agricultural", 
    documentPath: "/documents/rec_102_1.pdf", 
    documentTitle: "Certified Extract of Patta / Chitta Record",
    documentClassification: "Public",
    verificationStatus: "Verified",
    documentHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    issuedDate: "2024-01-15",
    lastModifiedBy: "Anitha Sundaram", 
    lastModifiedAt: "2026-05-10T11:00:00Z", 
    status: "Active",
    pattaNumber: "Patta-102-001",
    chittaNumber: "Chitta-102-001",
    pattaDocumentPath: "/documents/patta/PATTA-102-001.txt",
    chittaDocumentPath: "/documents/chitta/CHITTA-102-001.txt",
    fmbCopyPath: "/documents/fmb/rec_102_1_fmb_copy.txt"
  },
  { 
    id: "rec2", 
    surveyNumber: "204/3B", 
    ownerName: "Priya Govindan", 
    ownerPhone: "+91 98401 55667", 
    villageId: "v1", 
    villageName: "Mudichur", 
    district: "Kancheepuram",
    taluk: "Tambaram",
    area: "0.45 Acres", 
    landType: "Residential", 
    documentPath: "/documents/rec_204_3b.pdf", 
    documentTitle: "Residential Title Deed & Mutation Assessment",
    documentClassification: "Restricted",
    verificationStatus: "Pending Mutation",
    documentHash: "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
    issuedDate: "2023-11-20",
    lastModifiedBy: "Suresh Pillai", 
    lastModifiedAt: "2026-07-19T09:30:00Z", 
    status: "Active",
    pattaNumber: "Patta-204-03B",
    chittaNumber: "Chitta-204-03B",
    pattaDocumentPath: "/documents/patta/PATTA-102-001.txt",
    chittaDocumentPath: "/documents/chitta/CHITTA-102-001.txt",
    fmbCopyPath: "/documents/fmb/rec_102_1_fmb_copy.txt"
  },
  { 
    id: "rec3", 
    surveyNumber: "58/2", 
    ownerName: "Selvaraj Murugan", 
    ownerPhone: "+91 98412 88990", 
    villageId: "v2", 
    villageName: "Manapakkam", 
    district: "Kancheepuram",
    taluk: "Tambaram",
    area: "3.2 Acres", 
    landType: "Commercial", 
    documentPath: "/documents/rec_58_2.pdf", 
    documentTitle: "Commercial Land Register Extract & Tax Ledger",
    documentClassification: "Confidential",
    verificationStatus: "Verified",
    documentHash: "f0e1d2c3b4a5968778695a4b3c2d1e0fa1b2c3d4e5f60718293a4b5c6d7e8f9a",
    issuedDate: "2022-08-04",
    lastModifiedBy: "Balaji Rajan", 
    lastModifiedAt: "2026-03-12T14:20:00Z", 
    status: "Active",
    pattaNumber: "Patta-58-002",
    chittaNumber: "Chitta-58-002",
    pattaDocumentPath: "/documents/patta/PATTA-102-001.txt",
    chittaDocumentPath: "/documents/chitta/CHITTA-102-001.txt",
    fmbCopyPath: "/documents/fmb/rec_102_1_fmb_copy.txt"
  }
];

const SEED_MUTATIONS = [
  {
    id: "mut1",
    recordId: "rec2",
    surveyNumber: "204/3B",
    ownerName: "Priya Govindan",
    villageName: "Mudichur",
    area: "0.45 Acres",
    landType: "Residential",
    currentOwner: "Priya Govindan",
    proposedOwner: "Karthik Govindan",
    requestedBy: "u_citizen_001",
    requestedByName: "Ramesh Kumar",
    requestType: "Transfer",
    status: "Pending VAO",
    approved: false,
    remarks: "Transfer to legal heir following gift deed registration.",
    createdAt: "2026-07-19T09:30:00Z"
  }
];

async function seedAtlas() {
  console.log("================================================================================");
  console.log("             TRUSTGUARD - MONGODB ATLAS SEED & INITIALIZATION TOOL              ");
  console.log("================================================================================");
  console.log(`Connecting to: ${uri.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@')}`);
  console.log(`Target Database: ${dbName}\n`);

  const client = new MongoClient(uri);

  try {
    await client.connect();
    const db = client.db(dbName);
    await db.command({ ping: 1 });
    console.log("✔ Connected to MongoDB Atlas successfully!\n");

    // 1. Seed Users
    console.log(">>> Seeding Users collection...");
    const usersCol = db.collection("users");
    let usersInserted = 0;
    for (const u of SEED_USERS) {
      const res = await usersCol.updateOne(
        { email: u.email.toLowerCase() },
        { $setOnInsert: u },
        { upsert: true }
      );
      if (res.upsertedCount > 0) {
        usersInserted++;
        console.log(`   + Inserted: ${u.name.padEnd(20)} | ${u.email.padEnd(32)} | ${u.roleName}`);
      } else {
        console.log(`   = Existing: ${u.name.padEnd(20)} | ${u.email.padEnd(32)} | ${u.roleName}`);
      }
    }
    const totalUsers = await usersCol.countDocuments();
    console.log(`   Total Users in Atlas: ${totalUsers} (${usersInserted} newly added)\n`);

    // 2. Seed Land Records
    console.log(">>> Seeding Land Records collection...");
    const recordsCol = db.collection("land_records");
    for (const r of SEED_LAND_RECORDS) {
      await recordsCol.updateOne(
        { id: r.id },
        { $setOnInsert: r },
        { upsert: true }
      );
    }
    const totalRecords = await recordsCol.countDocuments();
    console.log(`   Total Land Records in Atlas: ${totalRecords}\n`);

    // 3. Seed Villages
    console.log(">>> Seeding Villages collection...");
    const villagesCol = db.collection("villages");
    for (const v of SEED_VILLAGES) {
      await villagesCol.updateOne(
        { id: v.id },
        { $setOnInsert: v },
        { upsert: true }
      );
    }
    const totalVillages = await villagesCol.countDocuments();
    console.log(`   Total Villages in Atlas: ${totalVillages}\n`);

    // 4. Seed Mutations
    console.log(">>> Seeding Mutations collection...");
    const mutationsCol = db.collection("mutations");
    for (const m of SEED_MUTATIONS) {
      await mutationsCol.updateOne(
        { id: m.id },
        { $setOnInsert: m },
        { upsert: true }
      );
    }
    const totalMutations = await mutationsCol.countDocuments();
    console.log(`   Total Mutations in Atlas: ${totalMutations}\n`);

    console.log("================================================================================");
    console.log("                         ATLAS SEEDING COMPLETED                               ");
    console.log("================================================================================");
    console.log("All official accounts are ready for cloud deployment login:");
    console.log("   • Tahsildar:         raj.kumar@revenue.tn.gov.in       (Password: Password@123)");
    console.log("   • VAO / Village:     balaji.vao@revenue.tn.gov.in      (Password: Password@123)");
    console.log("   • Deputy Tahsildar:  suresh.pillai@revenue.tn.gov.in   (Password: Password@123)");
    console.log("   • Revenue Inspector: anitha.ri@revenue.tn.gov.in       (Password: Password@123)");
    console.log("   • Data Entry:        kavitha.deo@revenue.tn.gov.in     (Password: Password@123)");
    console.log("   • System Admin:      admin@trustguard.gov.in           (Password: Password@123)");
    console.log("   • Citizen:           ramesh.citizen@gmail.com          (Password: Password@123)");
    console.log("================================================================================\n");

  } catch (err) {
    console.error("✖ MongoDB Atlas Seeding Failed:", err.message);
  } finally {
    await client.close();
  }
}

seedAtlas();
