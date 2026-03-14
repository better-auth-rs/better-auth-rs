/**
 * Configure a better-auth client pointing at AUTH_BASE_URL.
 *
 * Node/Bun fetch does not persist cookies across requests, so we wrap
 * the global fetch with a minimal cookie jar that captures `set-cookie`
 * response headers and resends them on subsequent requests.
 *
 * We also inject an `Origin` header on every request to satisfy
 * better-auth's CSRF protection, which requires it on POST requests.
 */

import { createAuthClient } from "better-auth/client";

const BASE_URL = process.env.AUTH_BASE_URL || "http://localhost:3100";

/**
 * Create a cookie-jar-aware fetch wrapper.
 *
 * Each call to `createCookieFetch()` returns a fresh jar so that tests
 * are isolated from one another.
 */
export function createCookieFetch() {
  /** @type {Map<string, string>} cookie name → "name=value" */
  const jar = new Map();

  return async (input, init) => {
    const headers = new Headers(init?.headers);

    // Attach stored cookies
    if (jar.size > 0) {
      const existing = headers.get("cookie") || "";
      const stored = [...jar.values()].join("; ");
      headers.set("cookie", existing ? `${existing}; ${stored}` : stored);
    }

    // Set Origin header for CSRF — in a real browser this is automatic
    if (!headers.has("origin")) {
      headers.set("origin", BASE_URL);
    }

    const res = await globalThis.fetch(input, { ...init, headers });

    // Capture set-cookie headers into the jar
    const setCookies = res.headers.getSetCookie?.() ?? [];
    for (const raw of setCookies) {
      const pair = raw.split(";")[0]; // "name=value"
      const eqIdx = pair.indexOf("=");
      if (eqIdx > 0) {
        const name = pair.slice(0, eqIdx).trim();
        jar.set(name, pair.trim());
      }
    }

    return res;
  };
}

/**
 * Build a better-auth client with a fresh cookie jar.
 */
export function createTestClient() {
  const fetchWithCookies = createCookieFetch();

  const client = createAuthClient({
    baseURL: BASE_URL,
    fetchOptions: {
      customFetchImpl: fetchWithCookies,
    },
  });

  return { client, fetch: fetchWithCookies };
}

export { BASE_URL };
