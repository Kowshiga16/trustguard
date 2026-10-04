/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import "dotenv/config";
import { randomInt } from "crypto";
import express from "express";
import path from "path";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { MongoClient, Db } from "mongodb";
import { createServer as createViteServer } from "vite";
import { 
  RoleName, 
  JurisdictionLevel, 
  User, 
  Village, 
  LandRecord, 
  MutationRequest, 
  ActiveSession, 
  TrustLog, 
  AuditLog,
  TrustAction,
  PropertyAsset,
  Application,
  ApplicationStatus,
  SecurityAlert
} from "./src/types";
import { trustConfig, RiskLevel, getRiskLevel, getPolicyDecisionForRisk, getRoleOtpThreshold } from "./services/trustConfig";
import { trustEngine } from "./services/trustEngine";
import { alertManager } from "./services/alertManager";
import { emailService, resolveActualRecipient } from "./services/emailService";
import { sessionActivityTracker } from "./services/sessionActivityTracker";
import { hybridTrustService } from "./services/hybridTrustService";

const PORT = parseInt(process.env.PORT || "3000", 10);
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/trustguard";
const MONGO_DB_NAME = process.env.MONGO_DB_NAME || "trustguard";
const JWT_SECRET = process.env.JWT_SECRET || "trustguard-local-dev-secret";
const JWT_TTL = process.env.JWT_TTL || "7d";

let mongoClient: MongoClient | null = null;
let mongoDb: Db | null = null;

async function initMongo() {
  try {
    mongoClient = new MongoClient(MONGO_URI);
    await mongoClient.connect();
    mongoDb = mongoClient.db(MONGO_DB_NAME);
    await mongoDb.command({ ping: 1 });
    console.log(`[MongoDB] Connected to ${MONGO_URI} using database ${MONGO_DB_NAME}`);
  } catch (error) {
    console.warn("[MongoDB] Connection failed. Falling back to in-memory data:", error);
    mongoClient = null;
    mongoDb = null;
  }
}

// In-memory Database Arrays
const villages: Village[] = [
  { id: "v1", name: "Mudichur", taluk: "Tambaram", district: "Kancheepuram" },
  { id: "v2", name: "Manapakkam", taluk: "Tambaram", district: "Kancheepuram" },
  { id: "v3", name: "Pennalur", taluk: "Sriperumbudur", district: "Kancheepuram" },
  { id: "v4", name: "Pillaipakkam", taluk: "Sriperumbudur", district: "Kancheepuram" },
  { id: "v5", name: "Gudalur", taluk: "Coimbatore South", district: "Coimbatore" },
];

const DEFAULT_PASSWORD_HASH = "$2b$10$JYbn94UeUTp7EGNdpHCLYucb99z.bn3NDklzw.Si8BoHrupEaW4yG"; // Bcrypt hash for "Password@123"

export const DEFAULT_USERS: User[] = [
  {
    id: "u_admin_001",
    name: "Admin Shrinivas",
    email: "admin@trustguard.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: RoleName.SystemAdministrator,
    phone: "9840011223",
    assignedJurisdiction: {
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1"
    },
    registeredDevice: "Admin-Workstation",
    properties: [],
    status: "Active"
  },
  {
    id: "u_tahsildar_001",
    name: "Raj Kumar",
    email: "raj.kumar@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: RoleName.Tahsildar,
    phone: "9840122334",
    assignedJurisdiction: {
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1"
    },
    registeredDevice: "Tahsildar-Laptop",
    properties: [],
    status: "Active"
  },
  {
    id: "u_dt_001",
    name: "Suresh Pillai",
    email: "suresh.pillai@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: RoleName.DeputyTahsildar,
    phone: "9840233445",
    assignedJurisdiction: {
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1"
    },
    registeredDevice: "Deputy-Laptop",
    properties: [],
    status: "Active"
  },
  {
    id: "u_ri_001",
    name: "Anitha Sundaram",
    email: "anitha.ri@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: RoleName.RevenueInspector,
    phone: "9840344556",
    assignedJurisdiction: {
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1"
    },
    registeredDevice: "RI-Field-Tablet",
    properties: [],
    status: "Active"
  },
  {
    id: "u_vao_001",
    name: "Balaji Rajan",
    email: "balaji.vao@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: RoleName.VillageAdministrativeOfficer,
    phone: "9840455667",
    assignedJurisdiction: {
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1"
    },
    registeredDevice: "VAO-Terminal-01",
    properties: [],
    status: "Active"
  },
  {
    id: "u_deo_001",
    name: "Kavitha Selvam",
    email: "kavitha.deo@revenue.tn.gov.in",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: RoleName.DataEntryOperator,
    phone: "9840566778",
    assignedJurisdiction: {
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1"
    },
    registeredDevice: "DEO-Desktop-02",
    properties: [],
    status: "Active"
  },
  {
    id: "u_citizen_001",
    name: "Ramesh Kumar",
    email: "ramesh.citizen@gmail.com",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: RoleName.Citizen,
    phone: "+91 98450 11223",
    assignedJurisdiction: {
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1"
    },
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
    roleName: RoleName.VillageAdministrativeOfficer,
    phone: "9998887776",
    assignedJurisdiction: {
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1"
    },
    registeredDevice: "Test-Device",
    properties: [],
    status: "Active"
  },
  {
    id: "u_tahsildar_test",
    name: "Test Tahsildar",
    email: "tahsildar@test.local",
    passwordHash: DEFAULT_PASSWORD_HASH,
    roleName: RoleName.Tahsildar,
    phone: "997688045",
    assignedJurisdiction: {
      district: "Kancheepuram",
      taluk: "Tambaram",
      villageId: "v1"
    },
    registeredDevice: "Tahsildar-Laptop",
    properties: [],
    status: "Active"
  }
];

let users: User[] = [...DEFAULT_USERS];

let landRecords: LandRecord[] = [
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
    verificationStatus: "Pending Verification",
    documentHash: "8a2f3b9c4d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a",
    issuedDate: "2024-03-22",
    lastModifiedBy: "Suresh Pillai", 
    lastModifiedAt: "2026-06-15T14:30:00Z", 
    status: "Active",
    pattaNumber: "Patta-204-003",
    chittaNumber: "Chitta-204-003",
    pattaDocumentPath: "/documents/patta/PATTA-204-003.txt",
    chittaDocumentPath: "/documents/chitta/CHITTA-204-003.txt",
    fmbCopyPath: "/documents/fmb/rec_204_3b_fmb_copy.txt"
  },
  { 
    id: "rec3", 
    surveyNumber: "88/2", 
    ownerName: "Rajesh Mehta", 
    ownerPhone: "+91 91234 56789", 
    villageId: "v2", 
    villageName: "Manapakkam", 
    district: "Kancheepuram",
    taluk: "Tambaram",
    area: "2.1 Acres", 
    landType: "Commercial", 
    documentPath: "/documents/rec_88_2.pdf", 
    documentTitle: "Commercial Land Registry & Revenue Sanction",
    documentClassification: "Confidential",
    verificationStatus: "Verified",
    documentHash: "4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    issuedDate: "2023-11-10",
    lastModifiedBy: "Suresh Pillai", 
    lastModifiedAt: "2026-04-02T09:15:00Z", 
    status: "Active",
    pattaNumber: "Patta-88-002",
    chittaNumber: "Chitta-88-002",
    pattaDocumentPath: "/documents/patta/PATTA-102-001.txt",
    chittaDocumentPath: "/documents/chitta/CHITTA-102-001.txt",
    fmbCopyPath: "/documents/fmb/rec_102_1_fmb_copy.txt"
  },
  { 
    id: "rec4", 
    surveyNumber: "114/A", 
    ownerName: "Sriperumbudur Farms Pvt Ltd", 
    ownerPhone: "+91 99940 12345", 
    villageId: "v3", 
    villageName: "Pennalur", 
    district: "Kancheepuram",
    taluk: "Sriperumbudur",
    area: "12.5 Acres", 
    landType: "Forest", 
    documentPath: "/documents/rec_114_a.pdf", 
    documentTitle: "Government Reserve Forest Demarcation Order",
    documentClassification: "Restricted",
    verificationStatus: "Verified",
    documentHash: "1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c",
    issuedDate: "2024-06-01",
    lastModifiedBy: "Balaji Rajan", 
    lastModifiedAt: "2026-02-18T16:45:00Z", 
    status: "Active",
    pattaNumber: "Patta-114-A",
    chittaNumber: "Chitta-114-A",
    pattaDocumentPath: "/documents/patta/PATTA-102-001.txt",
    chittaDocumentPath: "/documents/chitta/CHITTA-102-001.txt",
    fmbCopyPath: "/documents/fmb/rec_102_1_fmb_copy.txt"
  },
  { 
    id: "rec5", 
    surveyNumber: "50/4C", 
    ownerName: "Selvam Ramasamy", 
    ownerPhone: "+91 98410 98765", 
    villageId: "v4", 
    villageName: "Pillaipakkam", 
    district: "Kancheepuram",
    taluk: "Sriperumbudur",
    area: "3.2 Acres", 
    landType: "Agricultural", 
    documentPath: "/documents/rec_50_4c.pdf", 
    documentTitle: "Wetland Agricultural Holdings Registration",
    documentClassification: "Public",
    verificationStatus: "Pending Verification",
    documentHash: "7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e",
    issuedDate: "2025-02-14",
    lastModifiedBy: "Anitha Sundaram", 
    lastModifiedAt: "2026-07-01T10:00:00Z", 
    status: "Active",
    pattaNumber: "Patta-50-004",
    chittaNumber: "Chitta-50-004",
    pattaDocumentPath: "/documents/patta/PATTA-102-001.txt",
    chittaDocumentPath: "/documents/chitta/CHITTA-102-001.txt",
    fmbCopyPath: "/documents/fmb/rec_102_1_fmb_copy.txt"
  },
  { 
    id: "rec6", 
    surveyNumber: "77/5", 
    ownerName: "Venkat", 
    ownerPhone: "+91 98765 43210", 
    villageId: "v1", 
    villageName: "Mudichur", 
    district: "Kancheepuram",
    taluk: "Tambaram",
    area: "1.2 Acres", 
    landType: "Agricultural", 
    documentPath: "/documents/rec_77_5.pdf", 
    documentTitle: "Ancestral Dryland Patta Settlement",
    documentClassification: "Public",
    verificationStatus: "Verified",
    documentHash: "5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b",
    issuedDate: "2025-04-18",
    lastModifiedBy: "Anitha Sundaram", 
    lastModifiedAt: "2026-09-10T10:00:00Z", 
    status: "Active", 
    pattaNumber: "Patta-77-005",
    chittaNumber: "Chitta-77-005",
    pattaDocumentPath: "/documents/patta/PATTA-102-001.txt",
    chittaDocumentPath: "/documents/chitta/CHITTA-102-001.txt",
    fmbCopyPath: "/documents/fmb/rec_102_1_fmb_copy.txt"
  },
];

async function seedPropertiesIntoMongoUserCollection() {
  if (!mongoDb) return;

  const collection = mongoDb.collection<User>("users");
  const ramesh = users.find(u => u.email === "ramesh.citizen@gmail.com");
  if (!ramesh) return;

  await collection.updateOne(
    { email: ramesh.email },
    {
      $set: {
        name: ramesh.name,
        roleName: ramesh.roleName,
        phone: ramesh.phone,
        assignedJurisdiction: ramesh.assignedJurisdiction,
        registeredDevice: ramesh.registeredDevice,
        properties: ramesh.properties || []
      }
    },
    { upsert: true }
  );
}

let applications: Application[] = [];

let mutations: MutationRequest[] = [
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
    requestedBy: "u1",
    requestedByName: "Ramesh Kumar",
    requestType: "Transfer",
    status: "Pending VAO",
    approved: false,
    remarks: "Transfer to legal heir following gift deed registration.",
    createdAt: "2026-07-19T09:30:00Z"
  }
];

async function seedUsersIntoMongoCollection() {
  if (!mongoDb) return;

  const collection = mongoDb.collection<User>("users");
  for (const user of DEFAULT_USERS) {
    const existing = await collection.findOne({ 
      $or: [{ email: user.email.toLowerCase() }, { id: user.id }] 
    });
    if (!existing) {
      await collection.insertOne({ ...user });
      console.log(`[MongoDB Atlas] Seeded default user: ${user.email} (${user.roleName})`);
    }
  }
}

async function seedLandRecordsIntoMongoCollection() {
  if (!mongoDb) return;

  const collection = mongoDb.collection<LandRecord>("land_records");
  const count = await collection.countDocuments({});
  if (count === 0) {
    await collection.insertMany(landRecords);
    console.log(`[MongoDB Atlas] Seeded ${landRecords.length} default land records into Atlas`);
  } else {
    const dbRecords = await collection.find({}).toArray();
    if (dbRecords.length) {
      landRecords = dbRecords;
    }
  }
}

async function seedVillagesIntoMongoCollection() {
  if (!mongoDb) return;

  const collection = mongoDb.collection<Village>("villages");
  const count = await collection.countDocuments({});
  if (count === 0) {
    await collection.insertMany(villages);
    console.log(`[MongoDB Atlas] Seeded ${villages.length} villages into Atlas`);
  }
}

async function seedMutationsIntoMongoCollection() {
  if (!mongoDb) return;

  const collection = mongoDb.collection<MutationRequest>("mutations");
  const existingCount = await collection.countDocuments({});
  if (existingCount === 0) {
    await collection.insertMany(mutations);
    console.log(`[MongoDB Atlas] Seeded ${mutations.length} default mutations into Atlas`);
  }
}

async function loadUsersFromMongoIntoMemory() {
  if (!mongoDb) return;

  const dbUsers = await mongoDb.collection<User>("users").find({}).toArray();
  if (!dbUsers.length) return;

  for (const dbUser of dbUsers) {
    const existingIndex = users.findIndex(u => u.email === dbUser.email || u.id === dbUser.id);
    if (existingIndex >= 0) {
      users[existingIndex] = dbUser;
    } else {
      users.push(dbUser);
    }
  }
}

async function loadMutationsFromMongoIntoMemory() {
  if (!mongoDb) return;

  const collection = mongoDb.collection<MutationRequest>("mutations");
  const dbMutations = await collection.find({}).sort({ createdAt: 1 }).toArray();
  if (dbMutations.length) {
    mutations = dbMutations;
  }
}

let sessions: ActiveSession[] = [];
let trustLogs: TrustLog[] = [];
let auditLogs: AuditLog[] = [];
let securityAlerts: SecurityAlert[] = [];

function recordTrustLog(log: TrustLog) {
  trustLogs.unshift(log);
  if (mongoDb) {
    mongoDb.collection<TrustLog>("trust_logs").insertOne(log).catch(err => {
      console.warn("[MongoDB] Error writing trust log:", err.message);
    });
  }
}

function recordAuditLog(audit: AuditLog) {
  auditLogs.unshift(audit);
  if (mongoDb) {
    mongoDb.collection<AuditLog>("audit_logs").insertOne(audit).catch(err => {
      console.warn("[MongoDB] Error writing audit log:", err.message);
    });
  }
}

function recordSecurityAlert(alert: SecurityAlert) {
  securityAlerts.unshift(alert);
  alertManager.recordAlert(alert);
  if (mongoDb) {
    mongoDb.collection<SecurityAlert>("security_alerts").insertOne(alert).catch(err => {
      console.warn("[MongoDB] Error writing security alert:", err.message);
    });
  }
}

export interface SessionOtpRecord {
  code: string;
  expiresAt: number;
  createdAt: number;
  role: string;
  trustScore: number;
  roleThreshold: number;
  triggerSource: string;
  userEmail: string;
  emailSent: boolean;
  emailStatus: string;
  simulated: boolean;
}

const sessionOtpCodes = new Map<string, SessionOtpRecord>();

function generateOtp(): string {
  return randomInt(100000, 1000000).toString();
}

async function issueOtpForSession(
  session: ActiveSession, 
  triggerSource: string = "Dynamic Low-Trust Step-Up Verification"
): Promise<{ code: string; emailStatus: string; simulated: boolean }> {
  const code = generateOtp();
  const roleThreshold = getRoleOtpThreshold(session.role);
  const user = users.find(u => u.id === session.userId);
  const recipientEmail = resolveActualRecipient(session.userEmail || user?.email);

  const otpRecord: SessionOtpRecord = {
    code,
    expiresAt: Date.now() + 10 * 60 * 1000,
    createdAt: Date.now(),
    role: session.role,
    trustScore: session.currentTrustScore,
    roleThreshold,
    triggerSource,
    userEmail: recipientEmail,
    emailSent: false,
    emailStatus: "PENDING",
    simulated: false
  };

  sessionOtpCodes.set(session.id, otpRecord);

  // Dispatch OTP via NodeMailer
  try {
    const reasons = [
      `Trust score (${session.currentTrustScore}/100) is below role threshold (${roleThreshold}/100)`,
      triggerSource
    ];

    const sendResult = await emailService.sendOtpEmail({
      userName: session.userName,
      userEmail: recipientEmail,
      userRole: session.role,
      otpCode: code,
      currentTrustScore: session.currentTrustScore,
      roleThreshold,
      expiresInMinutes: 10,
      reasons,
      triggerContext: triggerSource,
      ipAddress: session.ipAddress,
      device: session.deviceFingerprint,
      timestamp: new Date().toISOString()
    });

    otpRecord.emailSent = sendResult.success;
    otpRecord.simulated = !!sendResult.simulated;
    otpRecord.emailStatus = sendResult.simulated ? "SIMULATED_LOGGED" : (sendResult.success ? "SENT" : "FAILED");

    // Record step-up OTP issuance in audit trail
    const audit: AuditLog = {
      id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `STEP_UP_OTP_ISSUED (Code dispatched to ${recipientEmail})`,
      resourceAccessed: "SECURITY_OTP_GATEWAY",
      trustScoreAtAction: session.currentTrustScore,
      decision: "STEP-UP OTP",
      timestamp: new Date().toISOString(),
      previousTrustScore: session.currentTrustScore,
      currentTrustScore: session.currentTrustScore,
      riskLevel: getRiskLevel(session.currentTrustScore),
      reasons,
      ipAddress: session.ipAddress,
      device: session.deviceFingerprint,
      emailAlertSent: sendResult.success,
      emailAlertDetails: {
        alertId: sendResult.messageId,
        recipient: recipientEmail,
        subject: `TrustGuard Security: Step-Up Identity Verification OTP [${code}]`,
        status: otpRecord.emailStatus as any,
        sentAt: new Date().toISOString()
      },
      policyAction: `Step-Up OTP Challenge Issued (${session.role} Threshold: ${roleThreshold})`
    };
    recordAuditLog(audit);

    return {
      code,
      emailStatus: otpRecord.emailStatus,
      simulated: otpRecord.simulated
    };
  } catch (err: any) {
    console.error("[NodeMailer OTP Error] Failed to dispatch OTP email:", err);
    otpRecord.emailSent = false;
    otpRecord.emailStatus = "FAILED";
    return {
      code,
      emailStatus: "FAILED",
      simulated: false
    };
  }
}

function getRequiredRoleForStatus(status: string): RoleName | null {
  switch (status) {
    case "Pending VAO":
      return RoleName.VillageAdministrativeOfficer;
    case "Pending RI":
      return RoleName.RevenueInspector;
    case "Pending Deputy Tahsildar":
      return RoleName.DeputyTahsildar;
    case "Pending Tahsildar":
      return RoleName.Tahsildar;
    default:
      return null;
  }
}

// Helper functions for logging and trust evaluation
function getSessionById(id: string): ActiveSession | undefined {
  return sessions.find(s => s.id === id);
}

function calculateTrustScore(session: ActiveSession): number {
  return trustEngine.calculateRuleBasedScore(session);
}

function logTrustChange(session: ActiveSession, eventType: string, previousScore: number, currentScore: number) {
  const diff = currentScore - previousScore;
  if (diff === 0) return;

  const log: TrustLog = {
    id: `tl_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
    sessionId: session.id,
    eventType,
    trustChangeValue: diff,
    resultingTrustScore: currentScore,
    timestamp: new Date().toISOString()
  };
  recordTrustLog(log);

  // If score drops significantly, create a security-themed audit entry
  if (diff < 0) {
    const risk = getRiskLevel(currentScore);
    const audit: AuditLog = {
      id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `TRUST_SCORE_DROP: ${eventType}`,
      resourceAccessed: "TRUST_ENGINE",
      trustScoreAtAction: currentScore,
      decision: currentScore < trustConfig.thresholds.criticalMax 
        ? "TERMINATED" 
        : (currentScore < trustConfig.thresholds.lowRiskMin ? "STEP-UP OTP" : "ALLOWED"),
      timestamp: new Date().toISOString(),
      previousTrustScore: previousScore,
      currentTrustScore: currentScore,
      riskLevel: risk,
      reasons: alertManager.extractReasons(session),
      ipAddress: session.ipAddress,
      device: session.deviceFingerprint,
      policyAction: getPolicyDecisionForRisk(risk)
    };
    recordAuditLog(audit);
  }
}

async function updateSessionTrust(
  session: ActiveSession, 
  eventType: string, 
  reqResource: string = "DYNAMIC_TRUST_ENGINE"
) {
  const prev = session.currentTrustScore;
  let ruleScore = trustEngine.calculateRuleBasedScore(session);
  const roleThreshold = getRoleOtpThreshold(session.role);

  if (eventType !== "OTP Identity Step-Up Succeeded" && session.otpVerified && ruleScore < roleThreshold) {
    session.otpVerified = false;
    sessionOtpCodes.delete(session.id);
  }

  const user = users.find(u => u.id === session.userId);
  const evaluation = await trustEngine.evaluateSessionTrust(session, eventType, user, reqResource);

  if (evaluation.trustLog) {
    recordTrustLog(evaluation.trustLog);
  }
  if (evaluation.auditEntry) {
    recordAuditLog(evaluation.auditEntry);
  }
  if (evaluation.securityAlert) {
    recordSecurityAlert(evaluation.securityAlert);
  }

  // If final trust score dropped below role OTP threshold and session is not verified,
  // automatically issue OTP via NodeMailer if no active code exists
  if (
    evaluation.finalScore < roleThreshold &&
    !session.otpVerified &&
    eventType !== "OTP Identity Step-Up Succeeded"
  ) {
    const existingOtp = sessionOtpCodes.get(session.id);
    if (!existingOtp || Date.now() >= existingOtp.expiresAt) {
      void issueOtpForSession(
        session,
        `Continuous Evaluation: Trust Score (${evaluation.finalScore}) below ${session.role} baseline (${roleThreshold})`
      );
    }
  }

  return evaluation;
}

// REST Server API SETUP
async function startServer() {
  await initMongo();
  if (mongoDb) {
    await seedUsersIntoMongoCollection();
    await seedVillagesIntoMongoCollection();
    await seedLandRecordsIntoMongoCollection();
    await seedMutationsIntoMongoCollection();
    await loadUsersFromMongoIntoMemory();
    await loadMutationsFromMongoIntoMemory();
    try {
      const dbAudits = await mongoDb.collection<AuditLog>("audit_logs").find({}).sort({ timestamp: -1 }).limit(100).toArray();
      if (dbAudits.length) {
        auditLogs = dbAudits;
      }
      const dbAlerts = await mongoDb.collection<SecurityAlert>("security_alerts").find({}).sort({ timestamp: -1 }).limit(50).toArray();
      if (dbAlerts.length) {
        securityAlerts = dbAlerts;
        for (const a of dbAlerts) {
          alertManager.recordAlert(a);
        }
      }
      const dbTrust = await mongoDb.collection<TrustLog>("trust_logs").find({}).sort({ timestamp: -1 }).limit(100).toArray();
      if (dbTrust.length) {
        trustLogs = dbTrust;
      }
    } catch (err: any) {
      console.warn("[MongoDB] Historical log load skipped:", err.message);
    }
  }

  const app = express();
  app.use(express.json({ strict: true }));
  app.use(express.urlencoded({ extended: true }));

  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (err instanceof SyntaxError && 'body' in err && (err as any).status === 400) {
      return res.status(400).json({
        error: 'invalid-json',
        message: 'Invalid JSON payload. Please send a properly formatted application/json request body.'
      });
    }
    return next(err);
  });

  // Log all requests to audit log
  app.use((req, res, next) => {
    // Exclude static assets and system routes
    if (req.path.startsWith("/api/")) {
      console.log(`[API REQUEST] ${req.method} ${req.path}`);
    }
    next();
  });

  // PDP and PEP Authorization Middleware
  const enforceZeroTrust = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: "unauthorized", message: "Missing session authorization header" });
      }

      const session = getSessionById(authHeader);
      if (!session) {
        return res.status(401).json({ error: "unauthorized", message: "Session expired or invalid" });
      }
      (req as any).session = session;

      // Refresh last activity time and track session request rate
      session.lastActivityTime = new Date().toISOString();
      sessionActivityTracker.recordRequest(session.id);

      if ((session.status === "Blocked" || session.currentTrustScore <= 50) && !session.otpVerified) {
        session.status = "Blocked";
        return res.status(403).json({
          error: "blocked",
          decision: "BLOCKED",
          message: `Your session has been locked due to critical trust degradation (Trust Score ${session.currentTrustScore} <= 50). Re-authentication required.`,
          trustScore: session.currentTrustScore,
          riskLevel: getRiskLevel(session.currentTrustScore)
        });
      }

      const currentIp = (req.headers['x-forwarded-for'] as string) || req.ip || "127.0.0.1";
      const currentUserAgent = req.headers['user-agent'] || "Unknown";

      if (session.realLoginIp && currentIp !== session.realLoginIp && !session.otpVerified) {
        session.simulatedIpMismatch = true;
      }
      if (session.realLoginUserAgent && currentUserAgent !== session.realLoginUserAgent && !session.otpVerified) {
        session.simulatedDeviceMismatch = true;
      }
      
      const features = sessionActivityTracker.extractFeatures(session);
      if ((features.requests_per_minute > 5 || features.downloads_count > 5) && !session.otpVerified) {
        session.simulatedSpamTriggered = true;
      }

      // Continuous Zero Trust Evaluation via TrustEngine & AlertManager
      const user = users.find(u => u.id === session.userId);
      const evaluation = await trustEngine.evaluateSessionTrust(session, "Continuous Evaluation", user, req.path);

      const hr = evaluation.hybridResult;

      if (evaluation.trustLog) {
        recordTrustLog(evaluation.trustLog);
      }
      if (evaluation.auditEntry) {
        // Phase 16: Enrich audit logs with ML & Hybrid variables
        evaluation.auditEntry.ruleRisk = hr.ruleRisk;
        evaluation.auditEntry.ruleTrust = hr.ruleTrust;
        evaluation.auditEntry.isolationForestScore = hr.isolationForestScore;
        evaluation.auditEntry.normalizedAnomalyScore = hr.normalizedAnomalyScore;
        evaluation.auditEntry.mlRisk = hr.mlRisk;
        evaluation.auditEntry.finalTrustScore = hr.finalTrustScore;
        evaluation.auditEntry.accessDecision = evaluation.policyDecision;
        evaluation.auditEntry.mlStatus = hr.mlServiceStatus;
        if (hr.featuresUsed) {
          evaluation.auditEntry.loginHour = hr.featuresUsed.login_hour;
          evaluation.auditEntry.recordsViewed = hr.featuresUsed.records_viewed;
          evaluation.auditEntry.downloadsCount = hr.featuresUsed.downloads_count;
          evaluation.auditEntry.requestsPerMinute = hr.featuresUsed.requests_per_minute;
          evaluation.auditEntry.failedOperations = hr.featuresUsed.failed_operations;
          evaluation.auditEntry.sessionDurationMinutes = hr.featuresUsed.session_duration_minutes;
        }
        recordAuditLog(evaluation.auditEntry);
      }
      if (evaluation.securityAlert) {
        recordSecurityAlert(evaluation.securityAlert);
      }

      const computedScore = session.currentTrustScore;
      const isWriteAction = ["POST", "PUT", "DELETE"].includes(req.method);
      const isAlertUpdate = req.path.startsWith("/api/security/alerts");
      const isSensitiveWrite = isWriteAction && !isAlertUpdate;

      // Separation of Duties / RBAC enforcement: Super Admin cannot alter land records
      if (session.role === RoleName.SystemAdministrator && req.path.startsWith("/api/records") && isWriteAction) {
        return res.status(403).json({
          error: "forbidden",
          message: "Security Constraint: System Administrator is barred from altering land database rows (Separation of Duties)."
        });
      }

      // Phase 14 & 15 Access Decision Logic
      // 0-50: TERMINATE_SESSION
      if (computedScore <= 50 || session.status === "Blocked") {
        session.status = "Blocked";
        const audit: AuditLog = {
          id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
          userId: session.userId,
          userName: session.userName,
          role: session.role,
          actionPerformed: `${req.method} ${req.path} (DENIED - BLOCKED)`,
          resourceAccessed: req.path,
          trustScoreAtAction: computedScore,
          decision: "TERMINATED",
          timestamp: new Date().toISOString(),
          previousTrustScore: evaluation.previousScore,
          currentTrustScore: computedScore,
          riskLevel: evaluation.riskLevel,
          reasons: evaluation.reasons,
          ipAddress: session.ipAddress,
          device: session.deviceFingerprint,
          policyAction: "Session Terminated due to Critical Security Degradation",
          ruleRisk: hr.ruleRisk, ruleTrust: hr.ruleTrust,
          isolationForestScore: hr.isolationForestScore, normalizedAnomalyScore: hr.normalizedAnomalyScore,
          mlRisk: hr.mlRisk, finalTrustScore: hr.finalTrustScore, accessDecision: "TERMINATE_SESSION", mlStatus: hr.mlServiceStatus
        };
        recordAuditLog(audit);
        return res.status(403).json({ 
          error: "blocked", 
          message: `Your session has been locked due to critical trust degradation (Trust Score ${computedScore} <= 50). Re-authentication required.`,
          trustScore: computedScore,
          riskLevel: evaluation.riskLevel
        });
      }

      // 51-60: OTP_REQUIRED (Step-up verification required for sensitive operations)
      if (computedScore >= 51 && computedScore <= 60 && isSensitiveWrite && !session.otpVerified) {
        const activeOtp = sessionOtpCodes.get(session.id);
        if (!activeOtp || Date.now() >= activeOtp.expiresAt) {
          void issueOtpForSession(session, `Zero Trust Step-Up (Score: ${computedScore})`);
        }

        const audit: AuditLog = {
          id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
          userId: session.userId,
          userName: session.userName,
          role: session.role,
          actionPerformed: `${req.method} ${req.path} (CHALLENGED - OTP REQUIRED)`,
          resourceAccessed: req.path,
          trustScoreAtAction: computedScore,
          decision: "STEP-UP OTP",
          timestamp: new Date().toISOString(),
          previousTrustScore: evaluation.previousScore,
          currentTrustScore: computedScore,
          riskLevel: evaluation.riskLevel,
          reasons: evaluation.reasons,
          ipAddress: session.ipAddress,
          device: session.deviceFingerprint,
          policyAction: `Step-Up OTP Verification Required for sensitive operation`,
          ruleRisk: hr.ruleRisk, ruleTrust: hr.ruleTrust,
          isolationForestScore: hr.isolationForestScore, normalizedAnomalyScore: hr.normalizedAnomalyScore,
          mlRisk: hr.mlRisk, finalTrustScore: hr.finalTrustScore, accessDecision: "OTP_REQUIRED", mlStatus: hr.mlServiceStatus
        };
        recordAuditLog(audit);
        return res.status(403).json({
          error: "step-up",
          message: `Step-up OTP verification required to perform sensitive operations (Score ${computedScore} is between 51-60). OTP dispatched via email.`,
          trustScore: computedScore,
          riskLevel: evaluation.riskLevel
        });
      }

      // 61-75: READ_ONLY (Writes completely blocked, cannot be bypassed with OTP)
      if (computedScore >= 61 && computedScore <= 75 && isSensitiveWrite) {
        session.failedActionCount += 1;
        await updateSessionTrust(session, "Unauthorized Write Attempt", req.path);

        const audit: AuditLog = {
          id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
          userId: session.userId,
          userName: session.userName,
          role: session.role,
          actionPerformed: `${req.method} ${req.path} (DENIED - READ ONLY)`,
          resourceAccessed: req.path,
          trustScoreAtAction: session.currentTrustScore,
          decision: "DENIED",
          timestamp: new Date().toISOString(),
          previousTrustScore: computedScore,
          currentTrustScore: session.currentTrustScore,
          riskLevel: getRiskLevel(session.currentTrustScore),
          reasons: ["Attempted write operation in Read-Only Trust tier (61-75)"],
          ipAddress: session.ipAddress,
          device: session.deviceFingerprint,
          policyAction: `Write operation denied. Full Access requires trust >= 76.`,
          ruleRisk: hr.ruleRisk, ruleTrust: hr.ruleTrust,
          isolationForestScore: hr.isolationForestScore, normalizedAnomalyScore: hr.normalizedAnomalyScore,
          mlRisk: hr.mlRisk, finalTrustScore: hr.finalTrustScore, accessDecision: "READ_ONLY", mlStatus: hr.mlServiceStatus
        };
        recordAuditLog(audit);

        return res.status(403).json({
          error: "read-only",
          message: `Write operation denied. Current trust level is READ-ONLY (${computedScore}/100). Full Access requires trust >= 76.`,
          trustScore: session.currentTrustScore,
          riskLevel: getRiskLevel(session.currentTrustScore)
        });
      }

      // Attach session to request for downstream route usage
      (req as any).session = session;
      next();
    } catch (err) {
      next(err);
    }
  };

  // Database health and metadata
  app.get("/api/health/db", async (req, res) => {
    res.json({
      mode: mongoDb ? "mongo" : "memory",
      database: mongoDb ? mongoDb.databaseName : "memory",
      uri: MONGO_URI,
      connected: Boolean(mongoDb)
    });
  });

  // 1. Auth Endpoints
  app.get("/api/users", (req, res) => {
    res.json(users);
  });

  app.get("/api/villages", (req, res) => {
    res.json(villages);
  });

  app.get("/api/applications", enforceZeroTrust, (req, res) => {
    const session: ActiveSession = (req as any).session;
    const user = users.find(u => u.id === session.userId);
    if (!user) {
      return res.status(404).json({ error: "User profile missing" });
    }

    if (session.role === RoleName.Citizen) {
      return res.json(applications.filter(a => a.applicantId === user.id || a.applicantName === user.name));
    }

    if (session.role === RoleName.VillageAdministrativeOfficer) {
      const villageId = user.assignedJurisdiction.villageId;
      return res.json(applications.filter(a => a.village === villageId || a.village === villages.find(v => v.id === villageId)?.name));
    }

    return res.json(applications);
  });

  app.post("/api/applications", enforceZeroTrust, (req, res) => {
    const session: ActiveSession = (req as any).session;
    const user = users.find(u => u.id === session.userId);
    if (!user) {
      return res.status(404).json({ error: "User profile missing" });
    }

    if (session.role !== RoleName.Citizen) {
      return res.status(403).json({ error: "forbidden", message: "Only citizens can submit citizen applications." });
    }

    const { landRecordId, surveyNumber, applicationType, reason, supportingDocumentReference } = req.body;
    if (!landRecordId || !surveyNumber || !applicationType || !reason) {
      return res.status(400).json({ error: "invalid-application", message: "Land record, survey number, application type, and reason are required." });
    }

    const landRecord = landRecords.find(r => r.id === landRecordId);
    if (!landRecord || landRecord.ownerName !== user.name) {
      return res.status(403).json({ error: "forbidden", message: "Citizen may only apply for land records that belong to the logged-in citizen profile." });
    }

    const application: Application = {
      id: `APP-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      applicantName: user.name,
      applicantEmail: user.email,
      applicantId: user.id,
      landRecordId,
      surveyNumber,
      applicationType,
      reason,
      supportingDocumentReference,
      submissionDate: new Date().toISOString(),
      status: ApplicationStatus.Submitted,
      district: user.assignedJurisdiction.district,
      taluk: user.assignedJurisdiction.taluk,
      village: villages.find(v => v.id === user.assignedJurisdiction.villageId)?.name || landRecord.villageName
    };

    applications.push(application);

    const audit: AuditLog = {
      id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `APPLICATION_SUBMITTED: ${application.id}`,
      resourceAccessed: "APPLICATION_WORKFLOW",
      trustScoreAtAction: session.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString()
    };
    auditLogs.unshift(audit);

    return res.status(201).json(application);
  });

  async function createUserFromPayload(body: any) {
    const { name, email, password, roleName, phone, assignedJurisdiction, registeredDevice, properties } = body;
    if (!name || !email || !password || !roleName || !phone || !registeredDevice || !assignedJurisdiction) {
      return { error: "invalid-user", message: "Name, email, password, role, phone, device, and jurisdiction are required." };
    }

    if (!Object.values(RoleName).includes(roleName)) {
      return { error: "invalid-role", message: "Unsupported role selected." };
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const cleanPhone = String(phone).replace(/[\s\-\(\)]/g, "");
    
    const duplicateInMemory = users.find(u => 
      u.email.toLowerCase() === normalizedEmail || 
      String(u.phone).replace(/[\s\-\(\)]/g, "") === cleanPhone
    );
    let duplicateInMongo: User | null = null;

    if (mongoDb) {
      duplicateInMongo = await mongoDb.collection<User>("users").findOne({
        $or: [{ email: normalizedEmail }, { phone: phone }, { phone: cleanPhone }]
      });
    }

    if (duplicateInMemory || duplicateInMongo) {
      const match = duplicateInMemory || duplicateInMongo;
      const which = match?.email.toLowerCase() === normalizedEmail ? "email address" : "phone number";
      return { error: "duplicate-user", message: `A user with this ${which} already exists (${match?.name || "existing account"}).` };
    }

    const passwordHash = await bcrypt.hash(String(password), 10);

    const finalJurisdiction = {
      district: assignedJurisdiction?.district || "Kancheepuram",
      taluk: assignedJurisdiction?.taluk || "Tambaram",
      villageId: assignedJurisdiction?.villageId || undefined
    };

    const newUser: User = {
      id: `u${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      name: String(name).trim(),
      email: normalizedEmail,
      passwordHash,
      roleName,
      phone: String(phone).trim(),
      assignedJurisdiction: finalJurisdiction,
      registeredDevice: String(registeredDevice || "Officer_Workstation").trim(),
      properties: Array.isArray(properties) ? properties : []
    };

    users.push(newUser);

    if (mongoDb) {
      await mongoDb.collection<User>("users").insertOne(newUser);
    }

    const audit: AuditLog = {
      id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      userId: newUser.id,
      userName: newUser.name,
      role: newUser.roleName,
      actionPerformed: "USER_CREATED",
      resourceAccessed: "USER_REGISTRY",
      trustScoreAtAction: 100,
      decision: "ALLOWED",
      timestamp: new Date().toISOString(),
      previousTrustScore: 100,
      currentTrustScore: 100,
      riskLevel: "NORMAL",
      policyAction: "Officer account provisioned into government registry"
    };
    recordAuditLog(audit);

    return { success: true, user: newUser };
  }

  app.post("/api/auth/signup", async (req, res) => {
    req.body.roleName = RoleName.Citizen;
    const created = await createUserFromPayload(req.body);
    if ((created as any).error) {
      return res.status(400).json(created);
    }
    return res.status(201).json(created);
  });

  app.post("/api/admin/users", enforceZeroTrust, async (req, res) => {
    const session: ActiveSession = (req as any).session;
    if (session.role !== RoleName.SystemAdministrator) {
      return res.status(403).json({ error: "forbidden", message: "Only the System Administrator can create revenue department users." });
    }

    const roleName = String(req.body?.roleName || "");
    const allowedAdminRoles = [
      RoleName.DataEntryOperator,
      RoleName.VillageAdministrativeOfficer,
      RoleName.RevenueInspector,
      RoleName.DeputyTahsildar,
      RoleName.Tahsildar
    ];

    if (!allowedAdminRoles.includes(roleName as RoleName)) {
      return res.status(400).json({ error: "invalid-role", message: "Only revenue department user roles are allowed from the admin creation route." });
    }

    const created = await createUserFromPayload(req.body);
    if ((created as any).error) {
      return res.status(400).json(created);
    }
    return res.status(201).json(created);
  });

  app.post("/api/auth/login", async (req, res) => {
    const { userId, email, password, customDevice, customIp } = req.body;

    let user: User | undefined;

    if (userId) {
      user = users.find(u => u.id === userId);
    } else if (email && password) {
      const normalizedInput = String(email).trim().toLowerCase();
      user = users.find(u => u.email.toLowerCase() === normalizedInput || u.name.toLowerCase() === normalizedInput);

      if (!user && mongoDb) {
        const dbUser = await mongoDb.collection<User>("users").findOne({
          $or: [
            { email: normalizedInput },
            { name: { $regex: new RegExp(`^${normalizedInput}$`, 'i') } }
          ]
        });
        if (dbUser) {
          users.push(dbUser);
          user = dbUser;
        }
      }

      if (!user) {
        return res.status(401).json({ error: "invalid-credentials", message: "Invalid username/email or password." });
      }

      const storedHash = user.passwordHash || user.password || "";
      const passwordMatches = await bcrypt.compare(String(password), storedHash);
      if (!passwordMatches) {
        return res.status(401).json({ error: "invalid-credentials", message: "Invalid email or password." });
      }
    } else {
      return res.status(400).json({ error: "invalid-login", message: "Provide email/password, or a demo userId." });
    }

    if (!user) {
      return res.status(404).json({ error: "not-found", message: "User not found" });
    }

    sessions = sessions.filter(s => s.userId !== user.id);

    const device = customDevice || user.registeredDevice;
    const ip = customIp || "192.168.1.104";

    const isDeviceMismatch = Boolean(customDevice && customDevice !== user.registeredDevice);
    const isIpMismatch = Boolean(customIp && customIp !== "192.168.1.104");

    const jwtToken = jwt.sign({
      sub: user.id,
      email: user.email,
      role: user.roleName,
      district: user.assignedJurisdiction?.district,
      taluk: user.assignedJurisdiction?.taluk,
      village: user.assignedJurisdiction?.villageId
    }, JWT_SECRET, { expiresIn: JWT_TTL as any });

    const newSession: ActiveSession = {
      id: `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId: user.id,
      userName: user.name,
      userEmail: user.email,
      role: user.roleName,
      deviceFingerprint: device,
      ipAddress: ip,
      loginTime: new Date().toISOString(),
      lastActivityTime: new Date().toISOString(),
      currentTrustScore: 75,
      status: "Active",
      token: jwtToken,
      simulatedDeviceMismatch: isDeviceMismatch,
      simulatedIpMismatch: isIpMismatch,
      simulatedNightAccess: false,
      simulatedOutsideJurisdiction: false,
      simulatedSpamTriggered: false,
      simulatedIdleTriggered: false,
      failedActionCount: 0,
      otpVerified: false,
      realLoginIp: req.ip || req.headers['x-forwarded-for'] as string || "127.0.0.1",
      realLoginUserAgent: req.headers['user-agent'] || "Unknown"
    };

    const initialEval = await trustEngine.evaluateSessionTrust(
      newSession, 
      isDeviceMismatch ? "Login via Untrusted Device" : "Login via Registered Device", 
      user, 
      "/api/auth/login"
    );

    if (newSession.currentTrustScore < trustConfig.thresholds.criticalMax) {
      newSession.status = "Blocked";
    }

    sessions.push(newSession);

    if (initialEval.trustLog) recordTrustLog(initialEval.trustLog);
    if (initialEval.auditEntry) recordAuditLog(initialEval.auditEntry);
    if (initialEval.securityAlert) recordSecurityAlert(initialEval.securityAlert);

    const audit: AuditLog = {
      id: `al_${Date.now()}`,
      userId: user.id,
      userName: user.name,
      role: user.roleName,
      actionPerformed: "USER_LOGIN",
      resourceAccessed: "AUTH_GATEWAY",
      trustScoreAtAction: newSession.currentTrustScore,
      decision: newSession.status === "Blocked" ? "TERMINATED" : "ALLOWED",
      timestamp: new Date().toISOString(),
      ipAddress: newSession.ipAddress,
      device: newSession.deviceFingerprint,
      riskLevel: initialEval.riskLevel,
      policyAction: initialEval.policyDecision
    };
    recordAuditLog(audit);

    res.json({ session: newSession, user, token: jwtToken });
  });

  app.post("/api/auth/logout", (req, res) => {
    const { sessionId } = req.body;
    const session = getSessionById(sessionId);
    if (session) {
      session.status = "Expired";
      const audit: AuditLog = {
        id: `al_${Date.now()}`,
        userId: session.userId,
        userName: session.userName,
        role: session.role,
        actionPerformed: "USER_LOGOUT",
        resourceAccessed: "AUTH_GATEWAY",
        trustScoreAtAction: session.currentTrustScore,
        decision: "ALLOWED",
        timestamp: new Date().toISOString()
      };
      auditLogs.unshift(audit);
    }
    sessions = sessions.filter(s => s.id !== sessionId);
    sessionOtpCodes.delete(sessionId);
    sessionActivityTracker.clearSession(sessionId);
    res.json({ success: true });
  });

  app.get("/api/auth/current-session", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: "Missing session token" });
    }
    const session = getSessionById(authHeader);
    if (!session) {
      return res.status(401).json({ error: "Session not active" });
    }
    res.json(session);
  });

  // 2. Continuous Trust Engine Simulation Endpoints
  app.post("/api/simulation/toggle", async (req, res) => {
    const { sessionId, param, value } = req.body;
    const session = getSessionById(sessionId);
    if (!session) {
      return res.status(404).json({ error: "not-found", message: "Session not found" });
    }

    if (param === "simulatedDeviceMismatch") session.simulatedDeviceMismatch = value;
    else if (param === "simulatedIpMismatch") {
      session.simulatedIpMismatch = value;
      if (value) session.ipAddress = "10.244.52.8"; // Simulated change
      else session.ipAddress = "192.168.1.104";
    }
    else if (param === "simulatedNightAccess") session.simulatedNightAccess = value;
    else if (param === "simulatedOutsideJurisdiction") session.simulatedOutsideJurisdiction = value;
    else if (param === "simulatedSpamTriggered") session.simulatedSpamTriggered = value;
    else if (param === "simulatedIdleTriggered") session.simulatedIdleTriggered = value;
    else if (param === "clearPenalties") {
      session.failedActionCount = 0;
      session.otpVerified = false;
      session.simulatedDeviceMismatch = false;
      session.simulatedIpMismatch = false;
      session.simulatedNightAccess = false;
      session.simulatedOutsideJurisdiction = false;
      session.simulatedSpamTriggered = false;
      session.simulatedIdleTriggered = false;
      alertManager.clearCooldown(session.userId);
    }

    const eventMsg = param === "clearPenalties" 
      ? "Manual Threat Parameters Reset" 
      : `Threat Simulation: Toggle ${param.replace("simulated", "")} to ${value}`;

    await updateSessionTrust(session, eventMsg, "/api/simulation/toggle");

    res.json(session);
  });

  app.post("/api/simulation/spam-actions", async (req, res) => {
    const { sessionId } = req.body;
    const session = getSessionById(sessionId);
    if (!session) {
      return res.status(404).json({ error: "Session not found" });
    }

    session.simulatedSpamTriggered = true;
    await updateSessionTrust(session, "Rapid API Request Spikes (>25req/min)", "/api/simulation/spam-actions");
    res.json(session);
  });

  // 3. Security, Logs & OTP Endpoints
  app.get("/api/security/trust-logs", (req, res) => {
    res.json(trustLogs);
  });

  app.get("/api/security/audit-logs", (req, res) => {
    res.json(auditLogs);
  });

  // Dedicated endpoint to simulate low trust score for role and trigger NodeMailer OTP
  app.post("/api/simulation/trigger-otp-challenge", async (req, res) => {
    const { sessionId } = req.body;
    const session = getSessionById(sessionId);
    if (!session) {
      return res.status(404).json({ error: "Session not found" });
    }

    const roleThreshold = getRoleOtpThreshold(session.role);

    // Apply simulated anomaly to drop trust score below the role's threshold
    session.simulatedDeviceMismatch = true;
    session.simulatedIpMismatch = true;
    session.ipAddress = "10.244.52.8";
    session.otpVerified = false;

    // Re-evaluate session trust
    const evaluation = await updateSessionTrust(
      session,
      `Simulated Low Trust Score for Role ${session.role}`,
      "/api/simulation/trigger-otp-challenge"
    );

    // Explicitly issue OTP via NodeMailer
    const otpResult = await issueOtpForSession(
      session,
      `Threat Simulation: Role-Based Low Trust (${session.role} baseline: ${roleThreshold})`
    );

    res.json({
      success: true,
      session,
      roleThreshold,
      otpTriggered: true,
      emailStatus: otpResult.emailStatus,
      simulated: otpResult.simulated,
      message: `Low trust score simulated for ${session.role}. Real-time NodeMailer OTP dispatched to ${session.userEmail}.`
    });
  });

  app.get("/api/security/otp-status/:sessionId", (req, res) => {
    const session = getSessionById(req.params.sessionId);
    if (!session) {
      return res.status(404).json({ error: "Session not found" });
    }

    const roleThreshold = getRoleOtpThreshold(session.role);
    const activeOtp = sessionOtpCodes.get(session.id);
    const isExpired = activeOtp ? Date.now() >= activeOtp.expiresAt : true;

    res.json({
      role: session.role,
      roleThreshold,
      currentTrustScore: session.currentTrustScore,
      otpRequired: session.currentTrustScore < roleThreshold && !session.otpVerified,
      otpVerified: session.otpVerified,
      hasActiveOtp: !isExpired,
      emailStatus: activeOtp?.emailStatus || "NONE"
    });
  });

  app.post("/api/security/request-otp", async (req, res) => {
    const session = getSessionById(req.body.sessionId);
    if (!session) {
      return res.status(404).json({ error: "Session not found" });
    }

    const triggerSource = req.body.reason || "Manual Step-Up OTP Verification Request";
    const otpResult = await issueOtpForSession(session, triggerSource);
    const roleThreshold = getRoleOtpThreshold(session.role);

    res.json({ 
      success: true,
      userEmail: session.userEmail,
      role: session.role,
      roleThreshold,
      simulated: otpResult.simulated,
      message: `Real-time OTP generated and dispatched to ${session.userEmail} via NodeMailer.`
    });
  });

  app.post("/api/security/verify-otp", async (req, res) => {
    const { sessionId, otpCode } = req.body;
    const session = getSessionById(sessionId);
    if (!session) {
      return res.status(404).json({ error: "Session not found" });
    }

    const storedOtp = sessionOtpCodes.get(sessionId);
    const isOtpValid = storedOtp && Date.now() < storedOtp.expiresAt && otpCode === storedOtp.code;

    if (isOtpValid) {
      sessionOtpCodes.delete(sessionId);
      session.otpVerified = true;
      session.status = "Active";
      // Clear threat flags because identity has been verified via Step-Up OTP
      session.simulatedSpamTriggered = false;
      session.simulatedIdleTriggered = false;
      session.simulatedNightAccess = false;
      session.simulatedIpMismatch = false;
      session.simulatedDeviceMismatch = false;
      session.simulatedOutsideJurisdiction = false;
      session.failedActionCount = 0;

      // Synchronize current IP and User Agent so they match the verified session
      const currentIp = ((req.headers['x-forwarded-for'] as string)?.split(',')[0].trim()) || req.ip || session.ipAddress;
      const currentUserAgent = (req.headers['user-agent'] as string) || session.realLoginUserAgent;
      session.ipAddress = currentIp;
      session.realLoginIp = currentIp;
      if (currentUserAgent && currentUserAgent !== "Unknown") {
        session.deviceFingerprint = currentUserAgent;
        session.realLoginUserAgent = currentUserAgent;
      }

      sessionActivityTracker.clearSession(sessionId);
      alertManager.clearCooldown(session.userId);

      await updateSessionTrust(session, "OTP Identity Step-Up Succeeded", "/api/security/verify-otp");

      // Ensure verified session reflects high restored trust score
      if (session.currentTrustScore < 85) {
        session.currentTrustScore = 85;
      }
      session.status = "Active";

      const audit: AuditLog = {
        id: `al_${Date.now()}`,
        userId: session.userId,
        userName: session.userName,
        role: session.role,
        actionPerformed: "OTP_STEP_UP_VERIFIED",
        resourceAccessed: "SECURITY_OTP_GATEWAY",
        trustScoreAtAction: session.currentTrustScore,
        decision: "ALLOWED",
        timestamp: new Date().toISOString(),
        previousTrustScore: session.currentTrustScore,
        currentTrustScore: session.currentTrustScore,
        riskLevel: getRiskLevel(session.currentTrustScore),
        policyAction: "Identity Verified via Step-Up OTP - Temporary Access Restored"
      };
      recordAuditLog(audit);

      res.json({ success: true, session });
    } else {
      session.failedActionCount += 1;
      await updateSessionTrust(session, "Invalid OTP Attempt", "/api/security/verify-otp");

      const audit: AuditLog = {
        id: `al_${Date.now()}`,
        userId: session.userId,
        userName: session.userName,
        role: session.role,
        actionPerformed: "OTP_STEP_UP_FAILED",
        resourceAccessed: "SECURITY_OTP_GATEWAY",
        trustScoreAtAction: session.currentTrustScore,
        decision: "DENIED",
        timestamp: new Date().toISOString(),
        previousTrustScore: session.currentTrustScore,
        currentTrustScore: session.currentTrustScore,
        riskLevel: getRiskLevel(session.currentTrustScore),
        reasons: ["Invalid or expired OTP step-up authentication code"],
        policyAction: "Challenge Failed - Trust Score Penalized"
      };
      recordAuditLog(audit);

      res.status(400).json({ error: "invalid", message: "Invalid or expired OTP code." });
    }
  });

  // Security Alerts & NodeMailer Monitoring API Endpoints
  app.get("/api/security/alerts", (req, res) => {
    res.json(alertManager.getAlerts());
  });

  app.get("/api/security/trust-config", (req, res) => {
    res.json({
      thresholds: trustConfig.thresholds,
      alertPolicy: trustConfig.alertPolicy,
      smtp: {
        host: trustConfig.smtp.host ? trustConfig.smtp.host : "DEVELOPMENT MOCK (Console Logger)",
        port: trustConfig.smtp.port,
        secure: trustConfig.smtp.secure,
        from: trustConfig.smtp.from,
        securityAlertEmail: trustConfig.smtp.securityAlertEmail,
        enabled: trustConfig.smtp.enabled,
        isConfigured: Boolean(trustConfig.smtp.host && trustConfig.smtp.user)
      },
      ml: {
        serviceUrl: trustConfig.ml.serviceUrl,
        timeoutMs: trustConfig.ml.timeoutMs,
        weight: trustConfig.ml.weight
      }
    });
  });

  app.get("/api/security/hybrid-trust", async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: "unauthorized", message: "Missing session authorization header" });
      }
      const session = getSessionById(authHeader);
      if (!session) {
        return res.status(401).json({ error: "unauthorized", message: "Session expired or invalid" });
      }
      const result = await hybridTrustService.calculateHybridTrust(session);
      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: "hybrid_trust_error", message: err?.message || "Failed to calculate hybrid trust" });
    }
  });

  app.get("/api/health/email", async (req, res) => {
    const health = await emailService.verifyConnection();
    res.json({
      ...health,
      smtpHost: trustConfig.smtp.host || "mock-console",
      targetRecipient: trustConfig.smtp.securityAlertEmail,
      enabled: trustConfig.smtp.enabled
    });
  });

  app.post("/api/security/test-alert-email", async (req, res) => {
    const testData = {
      userName: req.body.userName || "Raj Kumar",
      userEmail: req.body.userEmail || "raj.kumar@revenue.tn.gov.in",
      userRole: req.body.userRole || "Tahsildar",
      previousTrustScore: req.body.previousTrustScore || 87,
      currentTrustScore: req.body.currentTrustScore || 48,
      riskLevel: req.body.riskLevel || "SUSPICIOUS",
      reasons: req.body.reasons || [
        "Unrecognized device fingerprint detected",
        "Unusual IP address / network route change detected",
        "Off-hours session access attempt",
        "Abnormal document access pattern"
      ],
      ipAddress: req.body.ipAddress || "10.244.52.8",
      location: req.body.location || "Tambaram, Kancheepuram (Official Office)",
      device: req.body.device || "Chrome 122 on Windows 11 (Untrusted Device)",
      timestamp: new Date().toISOString(),
      policyDecision: req.body.policyDecision || "Limited Access / Step-Up OTP Verification Required",
      requestResource: req.body.requestResource || "/api/records",
      recipientEmail: req.body.recipientEmail || trustConfig.smtp.securityAlertEmail
    };

    const result = await emailService.sendTrustScoreAlert(testData);
    res.json({
      success: result.success,
      messageId: result.messageId,
      simulated: result.simulated,
      error: result.error,
      alertPayload: testData
    });
  });

  // In-memory Document Rate Limiting (10 requests per 10 seconds sliding window)
  const docAccessRateMap = new Map<string, number[]>();
  function checkDocAccessRateLimit(sessionId: string, maxPerWindow = 10, windowMs = 10000): boolean {
    const now = Date.now();
    const timestamps = (docAccessRateMap.get(sessionId) || []).filter(t => now - t < windowMs);
    timestamps.push(now);
    docAccessRateMap.set(sessionId, timestamps);
    return timestamps.length <= maxPerWindow;
  }

  // 4. Land Records Endpoints (Enforces Zero Trust & RBAC)
  app.get("/api/records", enforceZeroTrust, (req, res) => {
    const session: ActiveSession = (req as any).session;
    const user = users.find(u => u.id === session.userId);

    if (!user) {
      return res.status(404).json({ error: "User profile missing" });
    }

    let filtered = [...landRecords];

    // Citizen Role: can only view their own records
    if (session.role === RoleName.Citizen) {
      filtered = landRecords.filter(r => r.ownerName === user.name);
    } 
    // Jurisdictional access limits
    else if (session.role === RoleName.VillageAdministrativeOfficer) {
      const vId = user.assignedJurisdiction.villageId;
      if (session.simulatedOutsideJurisdiction) {
        filtered = landRecords;
      } else {
        filtered = landRecords.filter(r => r.villageId === vId);
      }
    } 
    else if (session.role === RoleName.RevenueInspector) {
      const taluk = user.assignedJurisdiction.taluk;
      if (session.simulatedOutsideJurisdiction) {
        filtered = landRecords;
      } else {
        const vilIds = villages.filter(v => v.taluk === taluk).map(v => v.id);
        filtered = landRecords.filter(r => vilIds.includes(r.villageId));
      }
    }
    else if (session.role === RoleName.DeputyTahsildar || session.role === RoleName.Tahsildar) {
      const taluk = user.assignedJurisdiction.taluk;
      if (session.simulatedOutsideJurisdiction) {
        filtered = landRecords;
      } else {
        const vilIds = villages.filter(v => v.taluk === taluk).map(v => v.id);
        filtered = landRecords.filter(r => vilIds.includes(r.villageId));
      }
    }
    else if (session.role === RoleName.SystemAdministrator) {
      // System Admins have separation of duties: can view dashboard, but cannot view/modify actual land records values!
      filtered = []; // Deny record payloads to Admin as a security control
    }

    // Query parameter filtering
    const { surveyNumber, ownerName, villageId, district, status, classification, verificationStatus } = req.query;

    if (surveyNumber && typeof surveyNumber === "string" && surveyNumber.trim()) {
      filtered = filtered.filter(r => r.surveyNumber.toLowerCase().includes(surveyNumber.toLowerCase().trim()));
    }
    if (ownerName && typeof ownerName === "string" && ownerName.trim()) {
      filtered = filtered.filter(r => r.ownerName.toLowerCase().includes(ownerName.toLowerCase().trim()));
    }
    if (villageId && typeof villageId === "string" && villageId !== "all") {
      filtered = filtered.filter(r => r.villageId === villageId);
    }
    if (district && typeof district === "string" && district !== "all") {
      filtered = filtered.filter(r => (r.district || "").toLowerCase() === district.toLowerCase());
    }
    if (status && typeof status === "string" && status !== "all") {
      filtered = filtered.filter(r => r.status === status);
    }
    if (classification && typeof classification === "string" && classification !== "all") {
      filtered = filtered.filter(r => r.documentClassification === classification);
    }
    if (verificationStatus && typeof verificationStatus === "string" && verificationStatus !== "all") {
      filtered = filtered.filter(r => r.verificationStatus === verificationStatus);
    }

    // Log the read audit entry
    const audit: AuditLog = {
      id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `READ_LAND_RECORDS: returned ${filtered.length} records`,
      resourceAccessed: "LAND_DB_TABLE",
      trustScoreAtAction: session.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString()
    };
    auditLogs.unshift(audit);
    sessionActivityTracker.recordRecordView(session.id, filtered.length);
    res.json(filtered);
  });

  // Single record detail view endpoint
  app.get("/api/records/:id", enforceZeroTrust, (req, res) => {
    const session: ActiveSession = (req as any).session;
    const { id } = req.params;
    const record = landRecords.find(r => r.id === id);
    if (!record) {
      return res.status(404).json({ error: "not_found", message: "Land record not found" });
    }
    if (session.role === RoleName.SystemAdministrator) {
      return res.status(403).json({ error: "forbidden", message: "Separation of Duties: Admin cannot view record details" });
    }
    res.json(record);
  });

  // Comprehensive Document Access Control Endpoint
  app.get("/api/records/:id/view", enforceZeroTrust, async (req, res) => {
    const session: ActiveSession = (req as any).session;
    const user = users.find(u => u.id === session.userId);
    const { id } = req.params;
    const record = landRecords.find(r => r.id === id);

    // 1. Check record existence
    if (!record) {
      return res.status(404).json({ authorized: false, error: "not_found", message: "Requested land document does not exist." });
    }

    // 2. Capture server-side observed client IP & context
    const observedIp = ((req.headers['x-forwarded-for'] as string)?.split(',')[0].trim()) || req.ip || req.socket.remoteAddress || "127.0.0.1";
    const userAgent = (req.headers['user-agent'] as string) || "Unknown";

    // 3. Rate limiting check (Throttles rapid automated scraping)
    const withinLimit = checkDocAccessRateLimit(session.id, 10, 10000);
    if (!withinLimit) {
      session.simulatedSpamTriggered = true;
      const rateAudit: AuditLog = {
        id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
        userId: session.userId,
        userName: session.userName,
        role: session.role,
        actionPerformed: `VIEW_DOCUMENT_RATE_LIMITED: Survey ${record.surveyNumber}`,
        resourceAccessed: `RECORD_DOCUMENT_${record.id}`,
        trustScoreAtAction: session.currentTrustScore,
        decision: "RATE_LIMITED",
        timestamp: new Date().toISOString(),
        reasons: ["Excessive document view request frequency (>10 requests per 10 seconds)"],
        ipAddress: observedIp,
        device: session.deviceFingerprint
      };
      auditLogs.unshift(rateAudit);
      return res.status(429).json({
        authorized: false,
        decision: "RATE_LIMITED",
        message: "Document access velocity exceeded allowable threshold. Access temporarily throttled to prevent bulk scraping.",
        trustScore: session.currentTrustScore,
        riskLevel: getRiskLevel(session.currentTrustScore)
      });
    }

    // 4. Record behavioral activity for Scikit-Learn Isolation Forest tracker
    sessionActivityTracker.recordRecordView(session.id, 1);
    sessionActivityTracker.recordDownload(session.id, record.id, record.documentClassification);

    // 5. Dynamic Zero Trust & Isolation Forest Evaluation
    const evaluation = await trustEngine.evaluateSessionTrust(session, `Document View: Survey ${record.surveyNumber}`, user, req.path);
    const hr = evaluation.hybridResult;

    // 6. RBAC & Separation of Duties Policy Enforcement
    // 6a. System Administrator Separation of Duties
    if (session.role === RoleName.SystemAdministrator) {
      const deniedAudit: AuditLog = {
        id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
        userId: session.userId,
        userName: session.userName,
        role: session.role,
        actionPerformed: `VIEW_DOCUMENT_DENIED: Survey ${record.surveyNumber} (Separation of Duties)`,
        resourceAccessed: `RECORD_DOCUMENT_${record.id}`,
        trustScoreAtAction: session.currentTrustScore,
        decision: "DENIED",
        timestamp: new Date().toISOString(),
        reasons: ["Separation of Duties Policy: System Administrators are barred from inspecting certified land registry contents"],
        ipAddress: observedIp,
        device: session.deviceFingerprint,
        ruleRisk: hr.ruleRisk,
        mlRisk: hr.mlRisk,
        isolationForestScore: hr.isolationForestScore,
        normalizedAnomalyScore: hr.normalizedAnomalyScore,
        finalTrustScore: hr.finalTrustScore
      };
      auditLogs.unshift(deniedAudit);
      return res.status(403).json({
        authorized: false,
        decision: "DENIED",
        message: "Access Denied: Separation of Duties policy prevents System Administrators from inspecting certified citizen land documents.",
        trustScore: session.currentTrustScore,
        riskLevel: evaluation.riskLevel
      });
    }

    // 6b. Citizen role: only allow their own record
    if (session.role === RoleName.Citizen && user && record.ownerName !== user.name) {
      const deniedAudit: AuditLog = {
        id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
        userId: session.userId,
        userName: session.userName,
        role: session.role,
        actionPerformed: `VIEW_DOCUMENT_DENIED: Survey ${record.surveyNumber} (Unauthorized Citizen Access)`,
        resourceAccessed: `RECORD_DOCUMENT_${record.id}`,
        trustScoreAtAction: session.currentTrustScore,
        decision: "DENIED",
        timestamp: new Date().toISOString(),
        reasons: ["Citizens are restricted to accessing their own registered land records"],
        ipAddress: observedIp,
        device: session.deviceFingerprint,
        ruleRisk: hr.ruleRisk,
        mlRisk: hr.mlRisk,
        isolationForestScore: hr.isolationForestScore,
        normalizedAnomalyScore: hr.normalizedAnomalyScore,
        finalTrustScore: hr.finalTrustScore
      };
      auditLogs.unshift(deniedAudit);
      return res.status(403).json({
        authorized: false,
        decision: "DENIED",
        message: "Access Denied: You do not possess ownership authorization to inspect this land deed.",
        trustScore: session.currentTrustScore,
        riskLevel: evaluation.riskLevel
      });
    }

    // 6c. Sensitivity Clearance: Confidential documents require Trust Score >= 80 (Full Access tier)
    if (record.documentClassification === "Confidential" && session.currentTrustScore < 80) {
      const deniedAudit: AuditLog = {
        id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
        userId: session.userId,
        userName: session.userName,
        role: session.role,
        actionPerformed: `VIEW_DOCUMENT_DENIED: Survey ${record.surveyNumber} (Insufficient Trust Clearance for Confidential Document)`,
        resourceAccessed: `RECORD_DOCUMENT_${record.id}`,
        trustScoreAtAction: session.currentTrustScore,
        decision: "DENIED",
        timestamp: new Date().toISOString(),
        reasons: [`Confidential documents mandate Full Access Trust Level (Score >= 80). Current Trust Score: ${session.currentTrustScore}`],
        ipAddress: observedIp,
        device: session.deviceFingerprint,
        ruleRisk: hr.ruleRisk,
        mlRisk: hr.mlRisk,
        isolationForestScore: hr.isolationForestScore,
        normalizedAnomalyScore: hr.normalizedAnomalyScore,
        finalTrustScore: hr.finalTrustScore
      };
      auditLogs.unshift(deniedAudit);
      return res.status(403).json({
        authorized: false,
        decision: "DENIED",
        message: "Access Denied: This confidential government document requires a Full Access trust posture (Score >= 80).",
        trustScore: session.currentTrustScore,
        riskLevel: evaluation.riskLevel
      });
    }

    // 7. Policy Decision Checks: Blocked or Step-Up OTP
    if ((session.currentTrustScore <= 50 || session.status === "Blocked") && !session.otpVerified) {
      session.status = "Blocked";
      void issueOtpForSession(session, `Document View Blocked (Score: ${session.currentTrustScore})`);
      return res.status(403).json({
        authorized: false,
        decision: "BLOCKED",
        error: "blocked",
        message: "Access Denied: Session blocked due to critical trust degradation. Verification required.",
        trustScore: session.currentTrustScore,
        riskLevel: evaluation.riskLevel
      });
    }

    const roleThreshold = getRoleOtpThreshold(session.role);
    if (!session.otpVerified && (session.currentTrustScore <= roleThreshold || (session.currentTrustScore >= 51 && session.currentTrustScore <= 60))) {
      void issueOtpForSession(session, `Document View Step-Up (Score: ${session.currentTrustScore})`);
      return res.status(403).json({
        authorized: false,
        decision: "OTP_REQUIRED",
        error: "step-up",
        message: `Trust Score degraded (${session.currentTrustScore.toFixed(2)}). Step-up OTP authentication required before document release.`,
        trustScore: session.currentTrustScore,
        riskLevel: evaluation.riskLevel
      });
    }

    // 8. Authorization Succeeded: Grant access & log audit
    const allowAudit: AuditLog = {
      id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `VIEW_DOCUMENT: Survey ${record.surveyNumber}`,
      resourceAccessed: `RECORD_DOCUMENT_${record.id}`,
      trustScoreAtAction: session.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString(),
      reasons: ["Zero Trust evaluation verified: User authenticated, role permitted, trust clearance confirmed."],
      ipAddress: observedIp,
      device: session.deviceFingerprint,
      ruleRisk: hr.ruleRisk,
      mlRisk: hr.mlRisk,
      isolationForestScore: hr.isolationForestScore,
      normalizedAnomalyScore: hr.normalizedAnomalyScore,
      finalTrustScore: hr.finalTrustScore
    };
    auditLogs.unshift(allowAudit);

    // Return the authorized certified document payload without exposing unnecessary system secrets
    return res.json({
      authorized: true,
      decision: "ALLOWED",
      recordId: record.id,
      documentPayload: {
        title: "Government of Tamil Nadu - Department of Revenue and Disaster Management",
        documentType: "Certified Extract of Land Register (ROR)",
        surveyNumber: record.surveyNumber,
        ownerName: record.ownerName,
        village: record.villageName,
        taluk: record.taluk || "Tambaram",
        district: record.district || "Kancheepuram",
        extent: record.area,
        landType: record.landType,
        pattaNumber: record.pattaNumber || "Patta-" + record.id,
        chittaNumber: record.chittaNumber || "Chitta-" + record.id,
        classification: record.documentClassification || "Public",
        verificationStatus: record.verificationStatus || "Verified",
        documentHash: record.documentHash || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        digitalSeal: "TN-REV-ZTA-DIGITALLY-SIGNED-VALID",
        issuedDate: record.issuedDate || "2024-01-15",
        associatedDocuments: [
          { name: "Patta Extract", path: record.pattaDocumentPath, type: "PATTA" },
          { name: "Chitta Extract", path: record.chittaDocumentPath, type: "CHITTA" },
          { name: "FMB Field Map Copy", path: record.fmbCopyPath, type: "FMB" }
        ]
      },
      evaluation: {
        trustScore: session.currentTrustScore,
        riskLevel: evaluation.riskLevel,
        policyDecision: evaluation.policyDecision,
        ruleRisk: hr.ruleRisk,
        mlRisk: hr.mlRisk,
        isolationForestScore: hr.isolationForestScore,
        normalizedAnomalyScore: hr.normalizedAnomalyScore,
        isAnomaly: hr.isAnomaly,
        mlServiceStatus: hr.mlServiceStatus
      }
    });
  });

  app.post("/api/records", enforceZeroTrust, (req, res) => {
    const session: ActiveSession = (req as any).session;
    
    // Separation of Duties / RBAC enforcement
    if (session.role === RoleName.SystemAdministrator) {
      return res.status(403).json({ 
        error: "forbidden", 
        message: "Security Constraint: System Administrator is barred from altering land database rows (Separation of Duties)." 
      });
    }
    if (session.role !== RoleName.DataEntryOperator) {
      return res.status(403).json({ error: "forbidden", message: "Only Data Entry Operators can create new land records." });
    }

    const { surveyNumber, ownerName, ownerPhone, villageId, area, landType } = req.body;
    const village = villages.find(v => v.id === villageId);
    if (!village) {
      return res.status(400).json({ error: "invalid-village", message: "Village ID is invalid" });
    }

    const newRecord: LandRecord = {
      id: `rec${Date.now()}`,
      surveyNumber,
      ownerName,
      ownerPhone,
      villageId,
      villageName: village.name,
      area,
      landType,
      documentPath: `/documents/uploaded_${surveyNumber.replace("/", "_")}.pdf`,
      lastModifiedBy: session.userName,
      lastModifiedAt: new Date().toISOString(),
      status: "Active"
    };

    landRecords.push(newRecord);

    const audit: AuditLog = {
      id: `al_${Date.now()}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `CREATE_RECORD: survey=${surveyNumber}, owner=${ownerName}`,
      resourceAccessed: `LAND_RECORD_TABLE`,
      trustScoreAtAction: session.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString()
    };
    auditLogs.unshift(audit);

    res.status(201).json(newRecord);
  });

  app.put("/api/records/:id", enforceZeroTrust, (req, res) => {
    const session: ActiveSession = (req as any).session;
    const { id } = req.params;

    if (session.role === RoleName.SystemAdministrator) {
      return res.status(403).json({ 
        error: "forbidden", 
        message: "Security Constraint: System Administrator is barred from altering land database rows (Separation of Duties)." 
      });
    }

    const recordIndex = landRecords.findIndex(r => r.id === id);
    if (recordIndex === -1) {
      return res.status(404).json({ error: "not-found", message: "Land record not found" });
    }

    const { ownerName, area, landType, ownerPhone } = req.body;
    landRecords[recordIndex] = {
      ...landRecords[recordIndex],
      ownerName,
      ownerPhone,
      area,
      landType,
      lastModifiedBy: session.userName,
      lastModifiedAt: new Date().toISOString()
    };

    const audit: AuditLog = {
      id: `al_${Date.now()}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `UPDATE_RECORD: id=${id}, survey=${landRecords[recordIndex].surveyNumber}`,
      resourceAccessed: `LAND_RECORD_TABLE`,
      trustScoreAtAction: session.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString()
    };
    auditLogs.unshift(audit);

    res.json(landRecords[recordIndex]);
  });

  // 5. Mutation Workflows (Highest risk, critical controls)
  app.get("/api/mutations", enforceZeroTrust, (req, res) => {
    const session: ActiveSession = (req as any).session;
    const user = users.find(u => u.id === session.userId);

    if (!user) {
      return res.status(404).json({ error: "User profile missing" });
    }

    let filtered = [...mutations];

    if (session.role === RoleName.Citizen) {
      filtered = mutations.filter(m => m.requestedBy === session.userId);
    } 
    else if (session.role === RoleName.VillageAdministrativeOfficer) {
      const vId = user.assignedJurisdiction?.villageId;
      const vName = villages.find(v => v.id === vId)?.name || "";
      if (!session.simulatedOutsideJurisdiction) {
        const pendingVao = mutations.filter(m => m.status === "Pending VAO");
        filtered = vName ? pendingVao.filter(m => m.villageName === vName) : pendingVao;
      }
    }
    else if (session.role === RoleName.RevenueInspector) {
      const taluk = user.assignedJurisdiction?.taluk || "";
      const vilNames = villages.filter(v => v.taluk === taluk).map(v => v.name);
      if (!session.simulatedOutsideJurisdiction) {
        const pendingRi = mutations.filter(m => m.status === "Pending RI");
        filtered = taluk && vilNames.length ? pendingRi.filter(m => vilNames.includes(m.villageName)) : pendingRi;
      }
    }
    else if (session.role === RoleName.DeputyTahsildar) {
      const taluk = user.assignedJurisdiction?.taluk || "";
      const vilNames = villages.filter(v => v.taluk === taluk).map(v => v.name);
      if (!session.simulatedOutsideJurisdiction) {
        const pendingDt = mutations.filter(m => m.status === "Pending Deputy Tahsildar");
        filtered = taluk && vilNames.length ? pendingDt.filter(m => vilNames.includes(m.villageName)) : pendingDt;
      }
    }
    else if (session.role === RoleName.Tahsildar) {
      const taluk = user.assignedJurisdiction?.taluk || "";
      const vilNames = villages.filter(v => v.taluk === taluk).map(v => v.name);
      if (!session.simulatedOutsideJurisdiction) {
        const pendingTah = mutations.filter(m => m.status === "Pending Tahsildar");
        filtered = taluk && vilNames.length ? pendingTah.filter(m => vilNames.includes(m.villageName)) : pendingTah;
      }
    }

    res.json(filtered);
  });

  app.post("/api/records/:id/mutate-request", enforceZeroTrust, async (req, res) => {
    const session: ActiveSession = (req as any).session;
    const { id } = req.params;
    const { proposedOwner, requestType, remarks } = req.body;

    const record = landRecords.find(r => r.id === id);
    if (!record) {
      return res.status(404).json({ error: "not-found", message: "Land record not found" });
    }

    const newMutation: MutationRequest = {
      id: `mut${Date.now()}`,
      recordId: id,
      surveyNumber: record.surveyNumber,
      ownerName: record.ownerName,
      villageName: record.villageName,
      area: record.area,
      landType: record.landType,
      currentOwner: record.ownerName,
      proposedOwner,
      requestedBy: session.userId,
      requestedByName: session.userName,
      requestType,
      status: "Pending VAO",
      approved: false,
      remarks,
      createdAt: new Date().toISOString()
    };

    record.status = "Mutation Pending";
    mutations.push(newMutation);

    if (mongoDb) {
      await mongoDb.collection<MutationRequest>("mutations").insertOne(newMutation);
    }

    const audit: AuditLog = {
      id: `al_${Date.now()}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `SUBMIT_MUTATION_REQUEST: record=${id}, to=${proposedOwner}`,
      resourceAccessed: `MUTATION_TABLE`,
      trustScoreAtAction: session.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString()
    };
    auditLogs.unshift(audit);

    res.status(201).json(newMutation);
  });

  app.post("/api/mutations/:id/approve", enforceZeroTrust, async (req, res) => {
    const session: ActiveSession = (req as any).session;
    const { id } = req.params;

    const mutation = mutations.find(m => m.id === id);
    if (!mutation) {
      return res.status(404).json({ error: "not-found", message: "Mutation request not found" });
    }

    // Role progression verification
    let nextStatus: MutationRequest["status"] | null = null;
    let allowedRole: RoleName | null = null;

    if (mutation.status === "Pending VAO") {
      allowedRole = RoleName.VillageAdministrativeOfficer;
      nextStatus = "Pending RI";
    } else if (mutation.status === "Pending RI") {
      allowedRole = RoleName.RevenueInspector;
      nextStatus = "Pending Deputy Tahsildar";
    } else if (mutation.status === "Pending Deputy Tahsildar") {
      allowedRole = RoleName.DeputyTahsildar;
      nextStatus = "Pending Tahsildar";
    } else if (mutation.status === "Pending Tahsildar") {
      allowedRole = RoleName.Tahsildar;
      nextStatus = "Approved";
    }

    if (!allowedRole || session.role !== allowedRole) {
      session.failedActionCount += 1;
      await updateSessionTrust(session, "Unauthorized Mutation Phase Approval Attempt", req.path);

      const audit: AuditLog = {
        id: `al_${Date.now()}`,
        userId: session.userId,
        userName: session.userName,
        role: session.role,
        actionPerformed: `APPROVE_MUTATION: id=${id} (DENIED - WRONG ROLE)`,
        resourceAccessed: `MUTATION_TABLE`,
        trustScoreAtAction: session.currentTrustScore,
        decision: "DENIED",
        timestamp: new Date().toISOString(),
        previousTrustScore: session.currentTrustScore,
        currentTrustScore: session.currentTrustScore,
        riskLevel: getRiskLevel(session.currentTrustScore),
        reasons: [`Approval chain violation: ${session.role} attempted unauthorized approval of mutation in status: ${mutation.status}`],
        ipAddress: session.ipAddress,
        device: session.deviceFingerprint,
        policyAction: "Approval chain violation prevented"
      };
      recordAuditLog(audit);

      return res.status(403).json({ 
        error: "forbidden", 
        message: `Approval chain violation. Only ${allowedRole || "designated officer"} can approve mutations currently in status: ${mutation.status}.` 
      });
    }

    mutation.status = nextStatus!;
    mutation.approved = nextStatus === "Pending RI" || mutation.approved === true;
    if (nextStatus === "Pending RI") {
      mutation.approved = true;
    }
    mutation.remarks += `\n[Approved by ${session.role}: ${session.userName} on ${new Date().toLocaleDateString()}]`;

    // If fully approved, execute the ownership update in landRecords
    if (nextStatus === "Approved") {
      const record = landRecords.find(r => r.id === mutation.recordId);
      if (record) {
        record.ownerName = mutation.proposedOwner;
        record.status = "Active";
        record.lastModifiedBy = session.userName;
        record.lastModifiedAt = new Date().toISOString();
      }
      mutation.approvedBy = session.userName;
      mutation.approvalDate = new Date().toISOString();
    }

    if (mongoDb) {
      await mongoDb.collection<MutationRequest>("mutations").updateOne(
        { id: mutation.id },
        { $set: { status: mutation.status, approved: mutation.approved, remarks: mutation.remarks, approvedBy: mutation.approvedBy, approvalDate: mutation.approvalDate } }
      );
    }

    const audit: AuditLog = {
      id: `al_${Date.now()}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `APPROVE_MUTATION: id=${id}, resulting_status=${nextStatus}`,
      resourceAccessed: `MUTATION_TABLE`,
      trustScoreAtAction: session.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString()
    };
    auditLogs.unshift(audit);

    res.json(mutation);
  });

  // Reject workflow
  app.post("/api/mutations/:id/reject", enforceZeroTrust, async (req, res) => {
    const session: ActiveSession = (req as any).session;
    const { id } = req.params;
    const { reason } = req.body;

    const mutation = mutations.find(m => m.id === id);
    if (!mutation) {
      return res.status(404).json({ error: "not-found", message: "Mutation request not found" });
    }

    const expectedRole = getRequiredRoleForStatus(mutation.status);
    if (expectedRole && session.role !== expectedRole) {
      session.failedActionCount += 1;
      await updateSessionTrust(session, "Unauthorized Mutation Phase Rejection Attempt", req.path);

      const audit: AuditLog = {
        id: `al_${Date.now()}`,
        userId: session.userId,
        userName: session.userName,
        role: session.role,
        actionPerformed: `REJECT_MUTATION: id=${id} (DENIED - WRONG ROLE)`,
        resourceAccessed: `MUTATION_TABLE`,
        trustScoreAtAction: session.currentTrustScore,
        decision: "DENIED",
        timestamp: new Date().toISOString(),
        previousTrustScore: session.currentTrustScore,
        currentTrustScore: session.currentTrustScore,
        riskLevel: getRiskLevel(session.currentTrustScore),
        reasons: [`Rejection chain violation: ${session.role} attempted unauthorized rejection of mutation in status: ${mutation.status}`],
        ipAddress: session.ipAddress,
        device: session.deviceFingerprint,
        policyAction: "Unauthorized mutation rejection prevented"
      };
      recordAuditLog(audit);

      return res.status(403).json({
        error: "forbidden",
        message: `Rejection chain violation. Only ${expectedRole} can reject mutations currently in status: ${mutation.status}.`
      });
    }

    mutation.status = "Rejected";
    mutation.approved = false;
    mutation.remarks += `\n[Rejected by ${session.role}: ${session.userName} - Reason: ${reason || "Unspecified"}]`;

    const record = landRecords.find(r => r.id === mutation.recordId);
    if (record) {
      record.status = "Active";
    }

    if (mongoDb) {
      await mongoDb.collection<MutationRequest>("mutations").updateOne(
        { id: mutation.id },
        { $set: { status: mutation.status, approved: mutation.approved, remarks: mutation.remarks } }
      );
    }

    const audit: AuditLog = {
      id: `al_${Date.now()}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `REJECT_MUTATION: id=${id}, reason=${reason}`,
      resourceAccessed: `MUTATION_TABLE`,
      trustScoreAtAction: session.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString()
    };
    auditLogs.unshift(audit);

    res.json(mutation);
  });

  // 6. Administrator Admin panel overrides
  app.post("/api/admin/override-trust", (req, res) => {
    const adminSessionId = req.body.adminSessionId || req.headers.authorization;
    const { targetSessionId, overrideScore } = req.body;
    
    const adminSess = getSessionById(adminSessionId);
    if (!adminSess || adminSess.role !== RoleName.SystemAdministrator) {
      return res.status(403).json({ error: "forbidden", message: "Only System Administrators can override session trust." });
    }

    const targetSess = getSessionById(targetSessionId);
    if (!targetSess) {
      return res.status(404).json({ error: "not-found", message: "Target user session not found" });
    }

    const prev = targetSess.currentTrustScore;
    targetSess.currentTrustScore = parseInt(overrideScore);
    if (targetSess.currentTrustScore < trustConfig.thresholds.criticalMax) {
      targetSess.status = "Blocked";
    } else {
      targetSess.status = "Active";
    }

    logTrustChange(targetSess, `Admin Override by ${adminSess.userName}`, prev, targetSess.currentTrustScore);

    const audit: AuditLog = {
      id: `al_${Date.now()}`,
      userId: adminSess.userId,
      userName: adminSess.userName,
      role: adminSess.role,
      actionPerformed: `ADMIN_TRUST_OVERRIDE: target=${targetSess.userName}, from=${prev}, to=${overrideScore}`,
      resourceAccessed: `SESSION_STATE_STORE`,
      trustScoreAtAction: adminSess.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString()
    };
    recordAuditLog(audit);

    res.json(targetSess);
  });

  app.get("/api/admin/sessions", (req, res) => {
    const authHeader = req.headers.authorization;
    const session = getSessionById(authHeader || "");
    if (!session || session.role !== RoleName.SystemAdministrator) {
      return res.status(403).json({ error: "forbidden", message: "Only Administrators can view active sessions." });
    }
    res.json(sessions);
  });

  app.get("/api/system/stats", (req, res) => {
    const totalRecords = landRecords.length;
    const activeSessionsCount = sessions.filter(s => s.status === "Active").length;
    const pendingMutations = mutations.filter(m => m.status !== "Approved" && m.status !== "Rejected").length;
    const securityIncidentsCount = auditLogs.filter(a => ["DENIED", "TERMINATED", "STEP-UP OTP"].includes(a.decision)).length;
    const totalUsers = users.length;

    const docAudits = auditLogs.filter(a => (a.actionPerformed && a.actionPerformed.includes("VIEW_DOCUMENT")) || (a.resourceAccessed && a.resourceAccessed.includes("RECORD_DOCUMENT")));
    const totalDocumentAccessAttempts = docAudits.length;
    const successfulAccessAttempts = docAudits.filter(a => a.decision === "ALLOWED").length;
    const deniedAccessAttempts = docAudits.filter(a => a.decision !== "ALLOWED").length;

    const highRiskUsersCount = sessions.filter(s => s.currentTrustScore < 60 || s.status === "Blocked").length;
    const criticalSecurityIncidents = auditLogs.filter(a => a.decision === "TERMINATED" || a.riskLevel === "Critical").length;

    const averageTrustScore = sessions.length 
      ? Math.round(sessions.reduce((acc, s) => acc + s.currentTrustScore, 0) / sessions.length) 
      : 85;

    const recentTrustScoreChanges = trustLogs.length;
    const suspiciousAccessEvents = auditLogs.filter(a => a.decision !== "ALLOWED" || (a.normalizedAnomalyScore && a.normalizedAnomalyScore >= 0.5)).length;

    const anomalyAudits = auditLogs.filter(a => (a.normalizedAnomalyScore && a.normalizedAnomalyScore >= 0.5) || (a.mlRisk && a.mlRisk > 0));
    const anomalyDetectionCount = anomalyAudits.length;
    const auditsWithNAS = auditLogs.filter(a => typeof a.normalizedAnomalyScore === "number");
    const averageAnomalyScore = auditsWithNAS.length 
      ? Number((auditsWithNAS.reduce((acc, a) => acc + (a.normalizedAnomalyScore || 0), 0) / auditsWithNAS.length).toFixed(4))
      : 0.1283;

    res.json({
      totalRecords,
      activeSessionsCount,
      pendingMutations,
      securityIncidentsCount,
      totalUsers,
      totalDocumentAccessAttempts,
      successfulAccessAttempts,
      deniedAccessAttempts,
      highRiskUsersCount,
      criticalSecurityIncidents,
      averageTrustScore,
      recentTrustScoreChanges,
      suspiciousAccessEvents,
      anomalyDetectionCount,
      averageAnomalyScore
    });
  });

  app.get("/api/analytics/dashboard", (req, res) => {
    // 1. Most frequently accessed documents
    const docCounts: Record<string, { id: string; surveyNumber: string; count: number }> = {};
    for (const log of auditLogs) {
      if (log.resourceAccessed && log.resourceAccessed.startsWith("RECORD_DOCUMENT_")) {
        const id = log.resourceAccessed.replace("RECORD_DOCUMENT_", "");
        const rec = landRecords.find(r => r.id === id);
        if (!docCounts[id]) {
          docCounts[id] = { id, surveyNumber: rec ? rec.surveyNumber : id, count: 0 };
        }
        docCounts[id].count++;
      }
    }
    const mostAccessedDocuments = Object.values(docCounts).sort((a, b) => b.count - a.count).slice(0, 5);

    // 2. Security incidents by category
    const categories: Record<string, number> = {
      "Off-Hours Access": 0,
      "IP Mismatch": 0,
      "Device Fingerprint Mismatch": 0,
      "Spam / Velocity Anomaly": 0,
      "Jurisdiction Bypass": 0,
      "Separation of Duties": 0,
      "Insufficient Trust Level": 0
    };
    for (const log of auditLogs) {
      if (log.reasons) {
        for (const r of log.reasons) {
          if (r.toLowerCase().includes("off-hours") || r.toLowerCase().includes("night")) categories["Off-Hours Access"]++;
          else if (r.toLowerCase().includes("ip")) categories["IP Mismatch"]++;
          else if (r.toLowerCase().includes("device")) categories["Device Fingerprint Mismatch"]++;
          else if (r.toLowerCase().includes("velocity") || r.toLowerCase().includes("spam") || r.toLowerCase().includes("rate limit")) categories["Spam / Velocity Anomaly"]++;
          else if (r.toLowerCase().includes("jurisdiction")) categories["Jurisdiction Bypass"]++;
          else if (r.toLowerCase().includes("separation of duties")) categories["Separation of Duties"]++;
          else categories["Insufficient Trust Level"]++;
        }
      }
    }

    // 3. Trust Score Distribution
    const trustScoreDistribution = {
      "0-25": sessions.filter(s => s.currentTrustScore <= 25).length,
      "26-50": sessions.filter(s => s.currentTrustScore > 25 && s.currentTrustScore <= 50).length,
      "51-75": sessions.filter(s => s.currentTrustScore > 50 && s.currentTrustScore <= 75).length,
      "76-100": sessions.filter(s => s.currentTrustScore > 75).length
    };

    // 4. Risk Distribution
    const riskDistribution = {
      "Low": sessions.filter(s => getRiskLevel(s.currentTrustScore) === RiskLevel.Low).length,
      "Medium": sessions.filter(s => getRiskLevel(s.currentTrustScore) === RiskLevel.Medium).length,
      "High": sessions.filter(s => getRiskLevel(s.currentTrustScore) === RiskLevel.High).length,
      "Critical": sessions.filter(s => getRiskLevel(s.currentTrustScore) === RiskLevel.Critical).length
    };

    // 5. User activity by role
    const userActivityByRole: Record<string, number> = {};
    for (const log of auditLogs) {
      const role = log.role || "Unknown";
      userActivityByRole[role] = (userActivityByRole[role] || 0) + 1;
    }

    // 6. Access attempts over time (last 6 hourly windows)
    const accessTimeline: Array<{ time: string; attempts: number; denied: number }> = [];
    const now = Date.now();
    for (let i = 5; i >= 0; i--) {
      const start = new Date(now - (i + 1) * 3600000);
      const end = new Date(now - i * 3600000);
      const inWindow = auditLogs.filter(a => {
        const t = new Date(a.timestamp);
        return t >= start && t < end;
      });
      accessTimeline.push({
        time: `${end.getHours()}:00`,
        attempts: inWindow.length,
        denied: inWindow.filter(a => a.decision !== "ALLOWED").length
      });
    }

    res.json({
      mostAccessedDocuments,
      securityIncidentsByCategory: categories,
      trustScoreDistribution,
      riskDistribution,
      userActivityByRole,
      accessTimeline,
      recentAuditEvents: auditLogs.slice(0, 15)
    });
  });

  app.put("/api/security/alerts/:id/status", enforceZeroTrust, (req, res) => {
    const session: ActiveSession = (req as any).session;
    const { id } = req.params;
    const { status, notes } = req.body;

    if (session.role !== RoleName.SystemAdministrator && session.role !== RoleName.Tahsildar) {
      return res.status(403).json({ error: "forbidden", message: "Only administrators can update alert status." });
    }

    if (!["NEW", "INVESTIGATING", "RESOLVED"].includes(status)) {
      return res.status(400).json({ error: "invalid_status", message: "Status must be NEW, INVESTIGATING, or RESOLVED" });
    }

    const updated = alertManager.updateAlertStatus(id, status, session.userName, notes);
    if (!updated) {
      return res.status(404).json({ error: "not_found", message: "Alert not found" });
    }

    const audit: AuditLog = {
      id: `al_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
      userId: session.userId,
      userName: session.userName,
      role: session.role,
      actionPerformed: `ALERT_STATUS_UPDATE: Alert ${id} updated to ${status}`,
      resourceAccessed: `SECURITY_ALERT_${id}`,
      trustScoreAtAction: session.currentTrustScore,
      decision: "ALLOWED",
      timestamp: new Date().toISOString()
    };
    auditLogs.unshift(audit);

    res.json({ success: true, alertId: id, status, investigatedBy: session.userName, notes });
  });

  // Seed initial values to make sure there is audit history
  auditLogs.push({
    id: "al_seed_1",
    userId: "u8",
    userName: "Admin Shrinivas",
    role: RoleName.SystemAdministrator,
    actionPerformed: "SYSTEM_INITIALIZED",
    resourceAccessed: "SYSTEM_KERNEL",
    trustScoreAtAction: 100,
    decision: "ALLOWED",
    timestamp: new Date(Date.now() - 3600000).toISOString()
  });

  app.use("/documents", express.static(path.join(process.cwd(), "documents")));

  await seedPropertiesIntoMongoUserCollection();

  // Vite development / production asset mounting
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[TrustGuard] Full-Stack server booted at http://localhost:${PORT}`);
  });
}

startServer();

