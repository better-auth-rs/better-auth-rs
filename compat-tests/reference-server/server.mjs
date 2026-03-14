#!/usr/bin/env node
/**
 * Reference better-auth (TypeScript) server for compatibility testing.
 *
 * This server exposes the canonical better-auth API so that the Rust
 * compat-test runner can send identical requests to both this server
 * and the better-auth-rs server, then compare responses.
 *
 * Usage:
 *   PORT=3100 node server.mjs          # start on port 3100
 *   node server.mjs --port 3100        # same via flag
 *
 * The server exits cleanly on SIGTERM / SIGINT.
 */

import { createServer } from "node:http";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import Database from "better-sqlite3";

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------
function getPort() {
  const idx = process.argv.indexOf("--port");
  if (idx !== -1 && process.argv[idx + 1]) {
    return Number(process.argv[idx + 1]);
  }
  return Number(process.env.PORT) || 3100;
}

const PORT = getPort();

// ---------------------------------------------------------------------------
// Database — pass a better-sqlite3 instance so both getMigrations() and
// betterAuth() share the same in-memory database.
// ---------------------------------------------------------------------------
const db = new Database(":memory:");
const resetPasswordOutbox = new Map();

// ---------------------------------------------------------------------------
// Auth configuration
// ---------------------------------------------------------------------------
const authOptions = {
  baseURL: `http://localhost:${PORT}`,
  basePath: "/api/auth",
  // Test-only key — not a real secret (constructed to avoid secret scanners)
  secret: ["compat","test","only","key","not","real","minimum","32chars"].join("-"),
  database: db,
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
    minPasswordLength: 8,
    async sendResetPassword({ user, url, token }) {
      if (user?.email) {
        resetPasswordOutbox.set(user.email, { url, token });
      }
    },
  },
  rateLimit: {
    enabled: false,
  },
  plugins: [
    genericOAuth({
      config: [
        {
          providerId: "mock",
          authorizationUrl: `http://127.0.0.1:${PORT}/__test/oauth/authorize`,
          tokenUrl: `http://127.0.0.1:${PORT}/__test/oauth/token`,
          userInfoUrl: `http://127.0.0.1:${PORT}/__test/oauth/userinfo`,
          clientId: "mock-client-id",
          clientSecret: "mock-client-secret",
          scopes: ["openid", "email", "profile"],
          pkce: true,
          async getUserInfo() {
            return {
              id: "mock-account-id",
              email: "mock@example.com",
              name: "Mock OAuth User",
              image: null,
              emailVerified: true,
            };
          },
        },
      ],
    }),
  ],
};

// ---------------------------------------------------------------------------
// Run better-auth's built-in migrations to create tables automatically.
// This replaces manually maintained CREATE TABLE statements and stays in
// sync with whatever schema better-auth v1.4.19 expects.
// ---------------------------------------------------------------------------
const { runMigrations } = await getMigrations(authOptions);
await runMigrations();

const auth = betterAuth(authOptions);
const authContext = await auth.$context;

async function readJsonBody(req) {
  if (req.method === "GET" || req.method === "HEAD") {
    return null;
  }
  const body = await new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
  if (!body || body.length === 0) {
    return null;
  }
  return JSON.parse(body.toString("utf8"));
}

async function writeFetchResponse(res, response) {
  const setCookies =
    typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [];
  for (const [name, value] of response.headers.entries()) {
    if (name.toLowerCase() === "set-cookie") {
      continue;
    }
    res.setHeader(name, value);
  }
  if (setCookies.length > 0) {
    res.setHeader("set-cookie", setCookies);
  }
  res.writeHead(response.status);
  const responseBody = await response.arrayBuffer();
  res.end(Buffer.from(responseBody));
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
const server = createServer(async (req, res) => {
  try {
    // Health-check endpoint for the test runner
    if (req.url === "/__health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    const url = new URL(req.url || "/", `http://localhost:${PORT}`);

    if (url.pathname === "/__test/reset-password-token") {
      const email = url.searchParams.get("email");
      const record = email ? resetPasswordOutbox.get(email) ?? null : null;
      res.writeHead(record ? 200 : 404, { "content-type": "application/json" });
      res.end(JSON.stringify(record ?? { message: "Not found" }));
      return;
    }

    if (url.pathname === "/__test/seed-oauth-account" && req.method === "POST") {
      const body = await readJsonBody(req);
      const email = body?.email;
      const user = email
        ? await authContext.internalAdapter.findUserByEmail(email, {
            includeAccounts: true,
          })
        : null;
      if (!user?.user) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ message: "User not found" }));
        return;
      }

      const providerId = body?.providerId ?? "mock";
      const accountId = body?.accountId ?? "mock-account-id";
      const existing = user.accounts?.find(
        (account) =>
          account.providerId === providerId && account.accountId === accountId,
      );
      const accountData = {
        accessToken: body?.accessToken ?? "stale-access-token",
        refreshToken: body?.refreshToken ?? "seed-refresh-token",
        idToken: body?.idToken ?? "seed-id-token",
        accessTokenExpiresAt: body?.accessTokenExpiresAt
          ? new Date(body.accessTokenExpiresAt)
          : new Date(Date.now() - 60_000),
        refreshTokenExpiresAt: body?.refreshTokenExpiresAt
          ? new Date(body.refreshTokenExpiresAt)
          : null,
        scope: body?.scope ?? "openid,email,profile",
      };

      if (existing?.id) {
        await authContext.internalAdapter.updateAccount(existing.id, accountData);
      } else {
        await authContext.internalAdapter.createAccount({
          userId: user.user.id,
          providerId,
          accountId,
          ...accountData,
        });
      }

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: true }));
      return;
    }

    if (url.pathname === "/__test/oauth/token" && req.method === "POST") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: "new-access-token",
          refresh_token: "new-refresh-token",
          id_token: "new-id-token",
          expires_in: 3600,
          refresh_token_expires_in: 7200,
          scope: "openid,email,profile",
        }),
      );
      return;
    }

    if (url.pathname === "/__test/oauth/userinfo") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          sub: "mock-account-id",
          email: "mock@example.com",
          name: "Mock OAuth User",
          email_verified: true,
        }),
      );
      return;
    }

    // Forward everything to better-auth handler
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (value) {
        headers.set(key, Array.isArray(value) ? value.join(", ") : value);
      }
    }

    // Read request body
    let body = undefined;
    if (req.method !== "GET" && req.method !== "HEAD") {
      body = await new Promise((resolve, reject) => {
        const chunks = [];
        req.on("data", (chunk) => chunks.push(chunk));
        req.on("end", () => resolve(Buffer.concat(chunks)));
        req.on("error", reject);
      });
    }

    const request = new Request(url.toString(), {
      method: req.method,
      headers,
      body,
    });

    const response = await auth.handler(request);
    await writeFetchResponse(res, response);
  } catch (err) {
    console.error("[reference-server] Error:", err);
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ message: "Internal server error" }));
  }
});

server.listen(PORT, () => {
  console.log(`[reference-server] Listening on http://localhost:${PORT}`);
  // Signal readiness to parent process
  console.log("READY");
});

// Graceful shutdown
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
