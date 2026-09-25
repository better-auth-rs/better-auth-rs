#!/usr/bin/env bun

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Database } from "bun:sqlite";

const root = resolve(import.meta.dir, "../../../..");
const legacyRequire = createRequire(`${root}/compat-tests/client-tests/package.json`);
const referenceRequire = createRequire(`${root}/compat-tests/reference-server/package.json`);
const { betterAuth } = await import(pathToFileURL(legacyRequire.resolve("better-auth")).href);
const { getMigrations } = await import(pathToFileURL(legacyRequire.resolve("better-auth/db")).href);
const legacyVersion = legacyRequire("better-auth/package.json").version;
const referenceVersion = referenceRequire("better-auth/package.json").version;
const port = Number(process.env.TYPES_FIXTURE_PORT ?? 3194);
const referenceURL = `http://localhost:${port}`;

async function capture(
  version: string,
  baseURL: string,
  handler: (request: Request) => Promise<Response>,
  userAgent: string,
) {
  const signupResponse = await handler(new Request(`${baseURL}/api/auth/sign-up/email`, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": userAgent },
    body: JSON.stringify({
      name: "Types Fixture",
      email: "types-fixture@example.com",
      password: "fixture-password-123",
    }),
  }));
  assert.equal(signupResponse.status, 200, await signupResponse.clone().text());
  const cookie = signupResponse.headers.getSetCookie()
    .map((value) => value.split(";", 1)[0]).join("; ");
  assert.ok(cookie.includes("better-auth.session_token="));
  const sessionResponse = await handler(new Request(`${baseURL}/api/auth/get-session`, {
    headers: { cookie, "user-agent": userAgent },
  }));
  assert.equal(sessionResponse.status, 200);
  const anonymousResponse = await handler(new Request(`${baseURL}/api/auth/get-session`));
  assert.equal(anonymousResponse.status, 200);
  const signup = await signupResponse.json();
  const getSession = await sessionResponse.json();
  const unauthenticatedGetSession = await anonymousResponse.json();
  assert.equal(signup.user.id, getSession.user.id);
  assert.equal(signup.user.id, getSession.session.userId);
  assert.equal(signup.token, getSession.session.token);
  assert.equal(unauthenticatedGetSession, null);

  // Normalize only unstable identifiers, tokens and nonempty user-agent values.
  signup.user.id = getSession.user.id = getSession.session.userId = "fixture-user";
  getSession.session.id = "fixture-session";
  signup.token = getSession.session.token = "fixture-session-token";
  if (getSession.session.userAgent) getSession.session.userAgent = "fixture-client";
  return { version, signup, getSession, unauthenticatedGetSession };
}

const database = new Database(":memory:");
const legacyOptions = {
  baseURL: "http://localhost:3193",
  secret: "fixture-only-secret-at-least-32-characters",
  database,
  emailAndPassword: { enabled: true },
};
const { runMigrations } = await getMigrations(legacyOptions);
await runMigrations();
const legacyAuth = betterAuth(legacyOptions);
const legacyCapture = await capture(legacyVersion, legacyOptions.baseURL, legacyAuth.handler, "");
database.close();

// Own a fresh reference process so no existing test server or data is reset.
const reference = Bun.spawn([process.execPath, "run", "server.ts", "--port", String(port)], {
  cwd: `${root}/compat-tests/reference-server`,
  stdout: "pipe",
  stderr: "inherit",
});
let startupTimeout: ReturnType<typeof setTimeout> | undefined;
try {
  // server.ts emits READY only after successfully binding its listener. Read
  // that child's stdout so an existing server cannot satisfy readiness.
  const ready = new Promise<void>((resolve, reject) => {
    async function consumeOutput() {
      const decoder = new TextDecoder();
      let pending = "";
      for await (const chunk of reference.stdout) {
        pending += decoder.decode(chunk, { stream: true });
        const lines = pending.split("\n");
        pending = lines.pop() ?? "";
        if (lines.includes("READY")) resolve();
      }
      reject(new Error("Reference server closed stdout before becoming ready"));
    }
    // Continue draining stdout after READY while capture requests run.
    void consumeOutput().catch(reject);
  });
  await Promise.race([
    ready,
    reference.exited.then((code) => {
      throw new Error(`Reference server exited before capture (status ${code})`);
    }),
    new Promise<never>((_, reject) => {
      startupTimeout = setTimeout(() => reject(new Error("Reference server did not become ready")), 10_000);
    }),
  ]);
  assert.equal(reference.exitCode, null, "Reference server exited before capture");
  const referenceCapture = await capture(referenceVersion, referenceURL, fetch, "fixture-client");
  assert.equal(reference.exitCode, null, "Reference server exited during capture");
  const output = process.argv[2] ?? `${import.meta.dir}/core_auth_responses.json`;
  await Bun.write(output, `${JSON.stringify([legacyCapture, referenceCapture], null, 2)}\n`);
  console.log(`Wrote ${output}`);
} finally {
  if (startupTimeout !== undefined) clearTimeout(startupTimeout);
  reference.kill();
  await reference.exited;
}
