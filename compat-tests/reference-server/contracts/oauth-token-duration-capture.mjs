import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { observeValue } from "./device-where-capture.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";

const version = "1.7.6";
const now = 2_000_000_000_123;
const origin = "http://oauth-token-duration.test";
const tokenURL = "https://duration-provider.test/token";
const secret = "oauth-token-duration-contract-secret-at-least-32-characters";
const tables = ["user", "session", "account", "verification"];
const scenarios = [
  { name: "negative-submillisecond", responseDuration: -0.0005 },
  { name: "fallback-nan", fallbackDuration: NaN },
];

function errorObservation(error) {
  assert.ok(error instanceof Error);
  const keys = Object.getOwnPropertyNames(error).filter(key => key !== "stack");
  return {
    name: error.name, message: error.message, keys,
    properties: Object.fromEntries(keys.map(key => [key,
      error[key] instanceof Error ? errorObservation(error[key]) : observeValue(error[key]),
    ])),
  };
}

function requestMetadata(request) {
  return request === undefined ? undefined : {
    url: request.url, method: request.method, headers: [...request.headers],
    bodyUsed: request.bodyUsed,
  };
}

async function requestObservation(request) {
  return { ...requestMetadata(request), body: await request.clone().text() };
}

async function responseObservation(response) {
  return {
    status: response.status, statusText: response.statusText,
    headers: [...response.headers], cookies: response.headers.getSetCookie(), body: await response.text(),
  };
}

async function captureCase(backend, scenario) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  const record = event => events.push(observeValue(event));
  const snapshot = () => observeValue(Object.fromEntries(tables.map(model => [model,
    database ? database.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model],
  ])));
  const oldRefresh = "duration-old-refresh";
  const oldAccessExpiry = new Date(now - 1000);
  const oldRefreshExpiry = new Date(now + 7_200_000);
  const sessionToken = "duration-owner-session-token";
  const signature = createHmac("sha256", secret).update(sessionToken).digest("base64");
  const cookie = `better-auth.session_token=${encodeURIComponent(`${sessionToken}.${signature}`)}`;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(async (resource, init) => {
    const request = new Request(resource, init);
    assert.equal(request.url, tokenURL);
    const body = await request.clone().text();
    const grant = new URLSearchParams(body).get("grant_type");
    assert.ok(grant === "authorization_code" || grant === "refresh_token");
    const response = Response.json({
      token_type: "Bearer", access_token: `duration-${grant}-access`,
      refresh_token: "duration-new-refresh", id_token: "duration-new-id", scope: "openid email",
      ...(scenario.responseDuration === undefined ? {} : {
        expires_in: scenario.responseDuration, refresh_token_expires_in: scenario.responseDuration,
      }),
    });
    record({ kind: "token.http", request: await requestObservation(request), response: await responseObservation(response.clone()) });
    return response;
  }, originalFetch);
  let recordingHooks = false;
  const options = {
    database: database ?? memoryAdapter(memory), baseURL: origin, secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { expiresIn: 3600, updateAge: 600, cookieCache: { enabled: false } },
    plugins: [genericOAuth({ config: [{
      providerId: "duration", clientId: "duration-client", clientSecret: "duration-client-secret",
      authorizationUrl: "https://duration-provider.test/authorize", tokenUrl: tokenURL,
      ...(Object.hasOwn(scenario, "fallbackDuration") ? { accessTokenExpiresIn: scenario.fallbackDuration } : {}),
      async refreshTokenParams(context) {
        record({ kind: "refresh.params", hasContext: context !== undefined,
          headers: context?.headers === undefined ? undefined : [...context.headers],
          request: requestMetadata(context?.request),
        });
        return { duration_case: scenario.name };
      },
    }] })],
    databaseHooks: Object.fromEntries(tables.map(model => [model,
      Object.fromEntries(["create", "update", "delete"].map(operation => [operation, {
        before(data) { if (recordingHooks) record({ kind: "hook", model, operation, phase: "before", data }); },
        after(data) { if (recordingHooks) record({ kind: "hook", model, operation, phase: "after", data }); },
      }])),
    ])),
  };
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const context = await auth.$context;
    const provider = context.socialProviders.find(provider => provider.id === "duration");
    assert.ok(provider?.validateAuthorizationCode && provider.refreshAccessToken);
    const helpers = [];
    for (const [operation, invoke] of [
      ["exchange", () => provider.validateAuthorizationCode({
        code: "duration-code", redirectURI: `${origin}/api/auth/callback/duration`, codeVerifier: "duration-verifier",
      })],
      ["refresh", () => provider.refreshAccessToken(oldRefresh)],
    ]) {
      let outcome;
      try {
        const value = await invoke();
        if (scenario.responseDuration === undefined) {
          assert.equal(value.accessTokenExpiresAt, undefined);
          assert.equal(value.refreshTokenExpiresAt, undefined);
        } else {
          assert.equal(value.accessTokenExpiresAt.getTime(), now - 1);
          assert.equal(value.refreshTokenExpiresAt.getTime(), now - 1);
        }
        outcome = { kind: "returned", value: observeValue(value) };
      } catch (error) {
        if (error instanceof assert.AssertionError) throw error;
        outcome = { kind: "thrown", error: errorObservation(error) };
      }
      assert.equal(outcome.kind, "returned", JSON.stringify(outcome));
      helpers.push({ operation, outcome, events: events.splice(0), storage: snapshot() });
      assert.deepEqual(snapshot(), Object.fromEntries(tables.map(model => [model, []])));
    }
    const date = new Date(now);
    await context.adapter.create({ model: "user", forceAllowId: true, data: {
      id: "duration-owner", name: "Duration Owner", email: "owner@oauth-token-duration.test",
      emailVerified: true, image: null, createdAt: date, updatedAt: date,
    } });
    await context.adapter.create({ model: "session", forceAllowId: true, data: {
      id: "duration-session", userId: "duration-owner", token: sessionToken,
      expiresAt: new Date(now + 3_600_000), createdAt: date, updatedAt: date, ipAddress: null, userAgent: null,
    } });
    await context.adapter.create({ model: "account", forceAllowId: true, data: {
      id: "duration-account", accountId: "duration-subject", providerId: "duration", userId: "duration-owner",
      accessToken: "duration-old-access", refreshToken: oldRefresh, idToken: "duration-old-id",
      accessTokenExpiresAt: oldAccessExpiry, refreshTokenExpiresAt: oldRefreshExpiry,
      scope: "openid email profile", password: null, createdAt: date, updatedAt: date,
    } });
    const before = snapshot();
    assert.deepEqual(events, []);
    recordingHooks = true;
    const request = new Request(`${origin}/api/auth/refresh-token`, {
      method: "POST", headers: { origin, cookie, "content-type": "application/json", "x-duration-case": scenario.name },
      body: JSON.stringify({ accountId: "duration-account" }),
    });
    const observedRequest = await requestObservation(request);
    let outcome;
    try {
      outcome = { kind: "returned", response: await responseObservation(await auth.handler(request)) };
    } catch (error) {
      if (error instanceof assert.AssertionError) throw error;
      outcome = { kind: "thrown", error: errorObservation(error) };
    }
    const after = snapshot();
    assert.equal(outcome.kind, "returned", JSON.stringify(outcome));
    assert.equal(outcome.response.status, 200, JSON.stringify(outcome));
    const body = JSON.parse(outcome.response.body);
    const account = await context.adapter.findOne({ model: "account", where: [{ field: "id", value: "duration-account" }] });
    assert.ok(account);
    assert.equal(account.accessToken, "duration-refresh_token-access");
    assert.equal(account.refreshToken, "duration-new-refresh");
    assert.equal(account.scope, "openid email profile");
    assert.equal(account.id, "duration-account");
    assert.equal(account.userId, "duration-owner");
    assert.equal(account.accountId, "duration-subject");
    assert.equal(account.providerId, "duration");
    assert.equal(account.accessTokenExpiresAt.getTime(), scenario.responseDuration === undefined ? oldAccessExpiry.getTime() : now - 1);
    assert.equal(account.refreshTokenExpiresAt.getTime(), scenario.responseDuration === undefined ? oldRefreshExpiry.getTime() : now - 1);
    assert.equal(body.accessTokenExpiresAt, scenario.responseDuration === undefined ? undefined : new Date(now - 1).toISOString());
    assert.equal(body.refreshTokenExpiresAt, account.refreshTokenExpiresAt.toISOString());
    assert.deepEqual(outcome.response.cookies, []);
    for (const model of ["user", "session", "verification"]) assert.deepEqual(after[model], before[model]);
    assert.deepEqual(events.filter(event => event.kind === "hook").map(event => [event.model, event.operation, event.phase]),
      [["account", "update", "before"], ["account", "update", "after"]]);
    assert.equal(events.filter(event => event.kind === "refresh.params").length, 1);
    assert.equal(events.filter(event => event.kind === "token.http").length, 1);
    return { backend, scenario: observeValue(scenario), now, helpers, before,
      refresh: { request: observedRequest, outcome, events, account: observeValue(account) }, after,
    };
  } finally {
    globalThis.fetch = originalFetch;
    database?.close();
  }
}

export async function captureOAuthTokenDuration() {
  for (const name of ["better-auth", "@better-auth/core"]) {
    assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
  }
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const backend of ["memory", "sqlite"]) {
      for (const scenario of scenarios) cases.push(await captureCase(backend, scenario));
    }
    return { version, contract: {
      clock: "Date.now and new Date read one fixed millisecond clock; Date arithmetic retains TimeClip ordering",
      errors: "Capture name, message, own property names and values; exclude environment-specific stack formatting",
      callbacks: "Capture public refresh context headers and Request metadata; the HTTP request body is captured before the handler consumes it",
      sources: [
        "@better-auth/core/src/oauth2/utils.ts", "@better-auth/core/src/oauth2/refresh-access-token.ts",
        "better-auth/dist/plugins/generic-oauth/index.mjs", "better-auth/dist/api/routes/account.mjs",
        "@better-auth/core/src/db/adapter/factory.ts",
      ],
    }, cases };
  });
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the OAuth token duration fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureOAuthTokenDuration(), null, 2)}\n`);
}
