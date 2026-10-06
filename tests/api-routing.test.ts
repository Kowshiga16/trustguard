import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { sanitizeBaseUrl, resolveApiUrl, initializeApiInterceptor } from "../src/apiConfig.ts";

describe("Frontend Centralized API Base URL & Routing Verification", () => {
  const PROD_BACKEND = "https://trustguard-2jfi.onrender.com";

  const REQUIRED_ENDPOINTS = [
    "/api/users",
    "/api/villages",
    "/api/auth/current-session",
    "/api/auth/login",
    "/api/auth/signup",
    "/api/auth/logout",
    "/api/security/trust-logs",
    "/api/security/audit-logs",
    "/api/system/stats",
    "/api/records",
    "/api/applications",
    "/api/mutations",
    "/api/security/request-otp",
    "/api/security/verify-otp",
    "/api/security/hybrid-trust",
    "/api/simulation/toggle",
    "/api/simulation/spam-actions",
    "/api/simulation/trigger-otp-challenge"
  ];

  it("1. Sanitizes base URL correctly (trims, removes trailing slashes, guards against /api suffix)", () => {
    assert.equal(sanitizeBaseUrl(undefined), "");
    assert.equal(sanitizeBaseUrl(""), "");
    assert.equal(sanitizeBaseUrl("  "), "");
    assert.equal(sanitizeBaseUrl("https://trustguard-2jfi.onrender.com"), PROD_BACKEND);
    assert.equal(sanitizeBaseUrl("https://trustguard-2jfi.onrender.com/"), PROD_BACKEND);
    assert.equal(sanitizeBaseUrl("https://trustguard-2jfi.onrender.com///"), PROD_BACKEND);
    assert.equal(sanitizeBaseUrl("https://trustguard-2jfi.onrender.com/api"), PROD_BACKEND);
    assert.equal(sanitizeBaseUrl("https://trustguard-2jfi.onrender.com/api/"), PROD_BACKEND);
  });

  it("2. Verifies all 18 required endpoints route to the Render backend", () => {
    for (const endpoint of REQUIRED_ENDPOINTS) {
      const resolved = resolveApiUrl(endpoint, PROD_BACKEND);
      assert.equal(
        resolved,
        `${PROD_BACKEND}${endpoint}`,
        `Endpoint ${endpoint} must resolve to ${PROD_BACKEND}${endpoint}`
      );
    }
  });

  it("3. Specifically verifies /api/villages routes to Render backend and not frontend domain", () => {
    const resolved = resolveApiUrl("/api/villages", PROD_BACKEND);
    assert.equal(resolved, "https://trustguard-2jfi.onrender.com/api/villages");
    assert.ok(!resolved.startsWith("/api/villages"), "Must not remain relative to frontend domain");
  });

  it("4. Specifically verifies /api/auth/login routes to Render backend", () => {
    const resolved = resolveApiUrl("/api/auth/login", PROD_BACKEND);
    assert.equal(resolved, "https://trustguard-2jfi.onrender.com/api/auth/login");
  });

  it("5. Specifically verifies /api/security/request-otp routes to Render backend", () => {
    const resolved = resolveApiUrl("/api/security/request-otp", PROD_BACKEND);
    assert.equal(resolved, "https://trustguard-2jfi.onrender.com/api/security/request-otp");
  });

  it("6. Specifically verifies /api/security/verify-otp routes to Render backend", () => {
    const resolved = resolveApiUrl("/api/security/verify-otp", PROD_BACKEND);
    assert.equal(resolved, "https://trustguard-2jfi.onrender.com/api/security/verify-otp");
  });

  it("7. Ensures no duplicate /api/api/... URL is ever created", () => {
    // Even if user accidentally configured backend URL with /api suffix
    const baseWithApi = sanitizeBaseUrl("https://trustguard-2jfi.onrender.com/api");
    const resolved = resolveApiUrl("/api/villages", baseWithApi);
    assert.equal(resolved, "https://trustguard-2jfi.onrender.com/api/villages");
    assert.ok(!resolved.includes("/api/api/"), "URL must never contain duplicate /api/api/");
  });

  it("8. Ensures no double slash // is introduced", () => {
    const baseWithTrailingSlash = sanitizeBaseUrl("https://trustguard-2jfi.onrender.com/");
    const resolved = resolveApiUrl("/api/villages", baseWithTrailingSlash);
    assert.equal(resolved, "https://trustguard-2jfi.onrender.com/api/villages");
    assert.ok(!resolved.replace("https://", "").includes("//"), "URL must not contain accidental double slashes");
  });

  it("9. Preserves local development when VITE_API_BASE_URL is unset", () => {
    const emptyBase = "";
    const resolved = resolveApiUrl("/api/villages", emptyBase);
    assert.equal(resolved, "/api/villages", "When base URL is unset, relative path must be preserved for localhost");
  });

  it("10. Preserves external absolute URLs untouched", () => {
    const external = "https://external-service.org/v1/data";
    const resolved = resolveApiUrl(external, PROD_BACKEND);
    assert.equal(resolved, external, "Absolute URLs must remain unchanged");
  });

  it("11. Verifies global fetch interceptor preserves HTTP methods, headers, and request bodies", async () => {
    let capturedUrl = "";
    let capturedInit: RequestInit | undefined = undefined;

    // Set up mock window and fetch environment
    const fakeWindow: any = {
      fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
        capturedUrl = String(input);
        capturedInit = init;
        return { ok: true, status: 200, json: async () => ({ success: true }) } as any;
      }
    };
    (globalThis as any).window = fakeWindow;

    // Initialize interceptor
    initializeApiInterceptor(PROD_BACKEND);

    // Test POST request with headers and body (like /api/security/verify-otp)
    const postBody = JSON.stringify({ sessionId: "sess-123", otpCode: "654321" });
    await fakeWindow.fetch("/api/security/verify-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "sess-123" },
      body: postBody
    });

    assert.equal(capturedUrl, "https://trustguard-2jfi.onrender.com/api/security/verify-otp");
    assert.equal(capturedInit?.method, "POST");
    assert.deepEqual(capturedInit?.headers, { "Content-Type": "application/json", "Authorization": "sess-123" });
    assert.equal(capturedInit?.body, postBody);

    // Test GET request (like /api/security/hybrid-trust)
    await fakeWindow.fetch("/api/security/hybrid-trust", {
      headers: { "Authorization": "sess-123" }
    });

    assert.equal(capturedUrl, "https://trustguard-2jfi.onrender.com/api/security/hybrid-trust");
    assert.deepEqual(capturedInit?.headers, { "Authorization": "sess-123" });

    // Clean up mock window
    delete (globalThis as any).window;
  });
});
