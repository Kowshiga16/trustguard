/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * TrustGuard Centralized Authorization Service
 * Enforces role-based, ownership, and jurisdictional boundaries on land records.
 * Ensures cross-jurisdiction access attempts are strictly denied on the backend
 * BEFORE any protected document data or sensitive metadata can be returned.
 */

import { User, LandRecord, ActiveSession, RoleName, Village, LandRecordAccessDecision } from "../src/types";

/**
 * Centralized authorization validator for land record access.
 * Compares authenticated user's authorized administrative scope against
 * the requested land parcel's village, taluk, and district.
 */
export function authorizeLandRecordAccess(
  user: User,
  record: LandRecord,
  session?: ActiveSession,
  villagesList?: Village[]
): LandRecordAccessDecision {
  if (!user || !record) {
    return {
      authorized: false,
      decision: "DENIED",
      reason: "User or land record not found",
      code: "RECORD_NOT_FOUND",
      isCrossJurisdiction: false
    };
  }

  const role = session?.role || user.roleName;

  // Resolve record jurisdiction
  const matchingVillage = villagesList?.find(v => v.id === record.villageId);
  const recordVillageId = record.villageId || matchingVillage?.id || "";
  const recordVillageName = record.villageName || matchingVillage?.name || "";
  const recordTaluk = record.taluk || matchingVillage?.taluk || "";
  const recordDistrict = record.district || matchingVillage?.district || "";

  // Resolve user jurisdiction
  const userVillageId = user.assignedJurisdiction?.villageId || "";
  const userTaluk = user.assignedJurisdiction?.taluk || "";
  const userDistrict = user.assignedJurisdiction?.district || "";

  const recordJurisdiction = {
    district: recordDistrict,
    taluk: recordTaluk,
    villageId: recordVillageId,
    villageName: recordVillageName
  };

  const userJurisdiction = {
    district: userDistrict,
    taluk: userTaluk,
    villageId: userVillageId
  };

  // 1. Separation of Duties: System Administrators are barred from inspecting certified citizen land document contents
  if (role === RoleName.SystemAdministrator) {
    return {
      authorized: false,
      decision: "DENIED",
      reason: "Access Denied: Separation of Duties policy prevents System Administrators from inspecting certified citizen land documents.",
      code: "SEPARATION_OF_DUTIES",
      isCrossJurisdiction: false,
      userJurisdiction,
      recordJurisdiction
    };
  }

  // 2. Citizen: only records permitted by existing ownership/access rules
  if (role === RoleName.Citizen) {
    const isOwnerByName = Boolean(
      user.name && 
      record.ownerName && 
      record.ownerName.trim().toLowerCase() === user.name.trim().toLowerCase()
    );
    const isOwnerByProperty = Boolean(
      user.properties && 
      user.properties.some(p => p.id === record.id || (p.surveyNumber && p.surveyNumber === record.surveyNumber))
    );

    if (!isOwnerByName && !isOwnerByProperty) {
      return {
        authorized: false,
        decision: "DENIED",
        reason: "Access Denied: You do not possess ownership authorization to inspect this land deed.",
        code: "UNAUTHORIZED_CITIZEN_ACCESS",
        isCrossJurisdiction: false,
        userJurisdiction,
        recordJurisdiction
      };
    }
    return {
      authorized: true,
      decision: "ALLOWED",
      isCrossJurisdiction: false,
      userJurisdiction,
      recordJurisdiction
    };
  }

  // 3. Village Administrative Officer (VAO): assigned village or villages
  if (role === RoleName.VillageAdministrativeOfficer) {
    // Village check: recordVillageId must match userVillageId
    const isVillageMatch = Boolean(userVillageId && recordVillageId && userVillageId === recordVillageId);
    // District check: if user has assigned district, record must be in that district
    const isDistrictMatch = !userDistrict || !recordDistrict || (userDistrict.trim().toLowerCase() === recordDistrict.trim().toLowerCase());

    if (!isVillageMatch || !isDistrictMatch) {
      return {
        authorized: false,
        decision: "DENIED",
        reason: "Access Denied: This land record is outside your authorized jurisdiction. The access attempt has been recorded.",
        code: "UNAUTHORIZED_CROSS_JURISDICTION_ACCESS",
        isCrossJurisdiction: true,
        userJurisdiction,
        recordJurisdiction
      };
    }
    return {
      authorized: true,
      decision: "ALLOWED",
      isCrossJurisdiction: false,
      userJurisdiction,
      recordJurisdiction
    };
  }

  // 4. Revenue Inspector (RI): authorized jurisdiction according to existing configuration (Taluk / District)
  if (role === RoleName.RevenueInspector) {
    const isTalukMatch = !userTaluk || !recordTaluk || (userTaluk.trim().toLowerCase() === recordTaluk.trim().toLowerCase());
    const isDistrictMatch = !userDistrict || !recordDistrict || (userDistrict.trim().toLowerCase() === recordDistrict.trim().toLowerCase());

    if (!isTalukMatch || !isDistrictMatch) {
      return {
        authorized: false,
        decision: "DENIED",
        reason: "Access Denied: This land record is outside your authorized jurisdiction. The access attempt has been recorded.",
        code: "UNAUTHORIZED_CROSS_JURISDICTION_ACCESS",
        isCrossJurisdiction: true,
        userJurisdiction,
        recordJurisdiction
      };
    }
    return {
      authorized: true,
      decision: "ALLOWED",
      isCrossJurisdiction: false,
      userJurisdiction,
      recordJurisdiction
    };
  }

  // 5. Deputy Tahsildar & Tahsildar: configured administrative scope (Taluk / District)
  if (role === RoleName.DeputyTahsildar || role === RoleName.Tahsildar) {
    const isTalukMatch = !userTaluk || !recordTaluk || (userTaluk.trim().toLowerCase() === recordTaluk.trim().toLowerCase());
    const isDistrictMatch = !userDistrict || !recordDistrict || (userDistrict.trim().toLowerCase() === recordDistrict.trim().toLowerCase());

    if (!isTalukMatch || !isDistrictMatch) {
      return {
        authorized: false,
        decision: "DENIED",
        reason: "Access Denied: This land record is outside your authorized jurisdiction. The access attempt has been recorded.",
        code: "UNAUTHORIZED_CROSS_JURISDICTION_ACCESS",
        isCrossJurisdiction: true,
        userJurisdiction,
        recordJurisdiction
      };
    }
    return {
      authorized: true,
      decision: "ALLOWED",
      isCrossJurisdiction: false,
      userJurisdiction,
      recordJurisdiction
    };
  }

  // 6. Data Entry Operator (DEO): assigned village or taluk
  if (role === RoleName.DataEntryOperator) {
    const isVillageMatch = !userVillageId || (recordVillageId && userVillageId === recordVillageId);
    const isTalukMatch = !userTaluk || !recordTaluk || (userTaluk.trim().toLowerCase() === recordTaluk.trim().toLowerCase());
    const isDistrictMatch = !userDistrict || !recordDistrict || (userDistrict.trim().toLowerCase() === recordDistrict.trim().toLowerCase());

    if (!isVillageMatch || !isTalukMatch || !isDistrictMatch) {
      return {
        authorized: false,
        decision: "DENIED",
        reason: "Access Denied: This land record is outside your authorized jurisdiction. The access attempt has been recorded.",
        code: "UNAUTHORIZED_CROSS_JURISDICTION_ACCESS",
        isCrossJurisdiction: true,
        userJurisdiction,
        recordJurisdiction
      };
    }
    return {
      authorized: true,
      decision: "ALLOWED",
      isCrossJurisdiction: false,
      userJurisdiction,
      recordJurisdiction
    };
  }

  return {
    authorized: false,
    decision: "DENIED",
    reason: "Access Denied: Unrecognized role or unauthorized record access.",
    code: "UNAUTHORIZED_ROLE",
    isCrossJurisdiction: false,
    userJurisdiction,
    recordJurisdiction
  };
}
