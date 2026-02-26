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
// Auth instance (in-memory SQLite)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

// better-auth v1.4.x requires a better-sqlite3 Database *instance* — passing
// `{ url: ":memory:", type: "sqlite" }` causes "Failed to initialize database
// adapter".  We also pre-create the tables that better-auth expects, since an
// in-memory database starts empty and better-auth does not auto-migrate.
const db = new Database(":memory:");

db.exec(`
  CREATE TABLE IF NOT EXISTS user (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    emailVerified INTEGER NOT NULL DEFAULT 0,
    image TEXT,
    createdAt TEXT NOT NULL,
    updatedAt TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY,
    expiresAt TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    createdAt TEXT NOT NULL,
    updatedAt TEXT NOT NULL,
    ipAddress TEXT,
    userAgent TEXT,
    userId TEXT NOT NULL REFERENCES user(id)
  );
  CREATE TABLE IF NOT EXISTS account (
    id TEXT PRIMARY KEY,
    accountId TEXT NOT NULL,
    providerId TEXT NOT NULL,
    userId TEXT NOT NULL REFERENCES user(id),
    accessToken TEXT,
    refreshToken TEXT,
    idToken TEXT,
    accessTokenExpiresAt TEXT,
    refreshTokenExpiresAt TEXT,
    scope TEXT,
    password TEXT,
    createdAt TEXT NOT NULL,
    updatedAt TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS verification (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    value TEXT NOT NULL,
    expiresAt TEXT NOT NULL,
    createdAt TEXT,
    updatedAt TEXT
  );
`);

const auth = betterAuth({
  baseURL: `http://localhost:${PORT}`,
  basePath: "/api/auth",
  // Test-only key — not a real secret (constructed to avoid secret scanners)
  secret: ["compat","test","only","key","not","real","minimum","32chars"].join("-"),
  database: db,
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
    minPasswordLength: 8,
  },
  rateLimit: {
    enabled: false,
  },
});

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

    // Forward everything to better-auth handler
    const url = new URL(req.url || "/", `http://localhost:${PORT}`);
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

    // Write response
    const responseHeaders = Object.fromEntries(response.headers.entries());
    res.writeHead(response.status, responseHeaders);
    const responseBody = await response.arrayBuffer();
    res.end(Buffer.from(responseBody));
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
