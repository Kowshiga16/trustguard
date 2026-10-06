/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Centralized API Base URL and Request Resolution for TrustGuard
 *
 * Supports separated frontend (Render Static Site) and backend (Render Web Service).
 * In production: VITE_API_BASE_URL="https://trustguard-2jfi.onrender.com"
 * In development: defaults to "" so relative proxy or localhost monolith continues working.
 */

export function sanitizeBaseUrl(rawUrl?: string): string {
  if (!rawUrl) return "";
  let base = rawUrl.trim().replace(/\/+$/, "");
  // Guard against duplicate /api/api if user entered base URL with /api suffix
  if (base.endsWith("/api")) {
    base = base.slice(0, -4);
  }
  return base;
}

export function getRawBaseUrl(): string {
  // 1. Vite environment variables
  if (typeof import.meta !== "undefined") {
    const metaEnv = (import.meta as any).env;
    if (metaEnv?.VITE_API_BASE_URL) return metaEnv.VITE_API_BASE_URL;
    if (metaEnv?.REACT_APP_API_BASE_URL) return metaEnv.REACT_APP_API_BASE_URL;
  }

  // 2. Process environment variables (Node / test runner / CRA)
  if (typeof process !== "undefined" && process.env) {
    if (process.env.VITE_API_BASE_URL) return process.env.VITE_API_BASE_URL;
    if (process.env.REACT_APP_API_BASE_URL) return process.env.REACT_APP_API_BASE_URL;
  }

  // 3. Fallback when deployed on Render or cloud host (non-localhost)
  if (typeof window !== "undefined" && window.location && window.location.hostname) {
    const host = window.location.hostname.toLowerCase();
    if (host !== "localhost" && host !== "127.0.0.1" && !host.startsWith("192.168.") && !host.endsWith(".local")) {
      return "https://trustguard-2jfi.onrender.com";
    }
  }

  return "";
}

export const API_BASE_URL: string = sanitizeBaseUrl(getRawBaseUrl());

export function resolveApiUrl(url: string, baseUrl: string = API_BASE_URL): string {
  if (!url) return url;
  // If already absolute URL, never alter it
  if (url.startsWith("http://") || url.startsWith("https://")) {
    return url;
  }
  if (!baseUrl) {
    return url;
  }
  const cleanPath = url.startsWith("/") ? url : `/${url}`;
  return `${baseUrl}${cleanPath}`;
}

/**
 * Initializes global fetch interception so that all direct fetch calls
 * throughout the frontend (including child components) automatically route
 * /api/* requests to the configured API_BASE_URL.
 */
export function initializeApiInterceptor(baseUrl: string = API_BASE_URL): void {
  if (typeof window === "undefined" || !baseUrl) {
    return;
  }

  const originalFetch = window.fetch.bind(window);

  window.fetch = function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    if (typeof input === "string") {
      if (input.startsWith("/api/") || input.startsWith("api/")) {
        return originalFetch(resolveApiUrl(input, baseUrl), init);
      }
    } else if (input instanceof URL) {
      if (input.pathname.startsWith("/api/")) {
        const targetUrl = resolveApiUrl(`${input.pathname}${input.search}${input.hash}`, baseUrl);
        return originalFetch(targetUrl, init);
      }
    }
    return originalFetch(input, init);
  };
}
