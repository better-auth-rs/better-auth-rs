import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { deviceAuthorization, testUtils } from "better-auth/plugins";
import { z } from "zod";
import { withDeviceGrantDatabase } from "./device-grant-database.mjs";

const origin = "http://device-grant.test";
const secret = "ordinary-device-grant-secret-at-least-32-characters";
const deviceCode = "ordinary-grant-device";
const userCode = "ABCD2345";
const sessionLifetime = 600;
const json = value => JSON.parse(JSON.stringify(value));
export const deviceGrantInputs = [
  { mode: "authorized", transport: "http", body: { scope: "read", label: " Desk ", ignored: "drop" } },
  { mode: "fallback", transport: "http", body: { client_id: "ordinary-client", scope: "read" } },
  { mode: "authorized", transport: "native", body: { scope: "read", label: " Desk ", ignored: "drop" } },
  { mode: "fallback", transport: "native", body: { client_id: "ordinary-client", scope: "read" } },
];

export function observeGrantRow(row) {
  assert.ok(row, "The ordinary issued Device record exists");
  return {
    clientId: row.clientId, scope: row.scope, status: row.status,
    pollingInterval: row.pollingInterval, label: row.label,
    hasOwner: row.userId !== undefined && row.userId !== null,
  };
}

async function responseValue(response) {
  return {
    status: response.status,
    headers: [...response.headers].sort(([a], [b]) => a.localeCompare(b)),
    body: await response.json(),
  };
}

export async function withDeviceGrantFixture(input, backend, run) {
  const events = [];
  const callbackError = new Error(`ordinary ${input.failure} failure`);
  const configuration = {
    baseURL: origin, secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { expiresIn: sessionLifetime },
    plugins: [testUtils(), deviceAuthorization({
      generateDeviceCode: () => deviceCode,
      generateUserCode: () => userCode,
      validateClient(clientId) {
        events.push({ phase: "validateClient", clientId });
        return clientId === "ordinary-client" || clientId === "ordinary-grant-client";
      },
      onDeviceAuthRequest(clientId, scope) {
        events.push({ phase: "onDeviceAuthRequest", clientId, scope });
      },
      grant: {
        requestSchemaFields: { label: z.string().trim().optional() },
        deviceCodeSchemaFields: {
          label: { type: "string", required: false, defaultValue: "Stored display" },
        },
        async authorizeRequest({ ctx, request }) {
          events.push({ phase: "authorizeRequest", request: json(request),
            hasRequest: ctx.request !== undefined,
            originalBody: ctx.request ? await ctx.request.clone().text() : null });
          if (input.failure === "authorizeRequest") throw callbackError;
          if (input.mode === "fallback") return undefined;
          return { clientId: "ordinary-grant-client", deviceCodeFields: { label: request.label } };
        },
        assertSessionRedemption({ deviceCode: row }) {
          events.push({ phase: "assertSessionRedemption", row: observeGrantRow(row) });
          assert.equal(row.status, "approved");
          assert.equal(row.scope, "read");
          assert.ok(row.userId, "The approved Device record has its owner");
          if (input.failure === "assertSessionRedemption") throw callbackError;
        },
        getVerificationContext(row) {
          events.push({ phase: "getVerificationContext", row: observeGrantRow(row) });
          if (input.failure === "getVerificationContext") throw callbackError;
          return { label: row.label };
        },
      },
    })],
  };
  return await withDeviceGrantDatabase(backend, configuration, async auth => {
  const context = await auth.$context;
  const owner = await context.test.saveUser(context.test.createUser({
    name: "Device owner", email: "owner@device-grant.test",
  }));
  const login = await context.test.login({ userId: owner.id });
  const readRow = () => context.adapter.findOne({ model: "deviceCode",
    where: [{ field: "deviceCode", value: deviceCode }] });

  async function request(endpoint, method, path, body, query, authenticated = false) {
    const headers = authenticated ? new Headers(login.headers) : new Headers();
    if (input.transport === "native") {
      return await auth.api[endpoint]({
        body, query, headers, asResponse: true,
      });
    }
    headers.set("origin", origin);
    headers.set("accept", "application/json");
    if (body !== undefined) headers.set("content-type", "application/json");
    const url = new URL(`/api/auth${path}`, origin);
    if (query) url.search = new URLSearchParams(query).toString();
    return await auth.handler(new Request(url, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    }));
  }
  const call = async (...args) => responseValue(await request(...args));
  return await run({ auth, context, owner, events, callbackError, readRow, call, request });
  });
}

async function captureCase(input, backend) {
  return await withDeviceGrantFixture(input, backend, async ({ context, owner, events, readRow, call }) => {
  const issuance = await call("deviceCode", "POST", "/device/code", input.body);
  assert.equal(issuance.status, 200);
  const issued = observeGrantRow(await readRow());
  const verification = await call("deviceVerify", "GET", "/device", undefined,
    { user_code: userCode }, true);
  assert.equal(verification.status, 200);
  const claimed = observeGrantRow(await readRow());
  const approval = await call("deviceApprove", "POST", "/device/approve",
    { userCode }, undefined, true);
  assert.equal(approval.status, 200);
  const approved = observeGrantRow(await readRow());
  const started = Date.now();
  const redemption = await call("deviceToken", "POST", "/device/token", {
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    device_code: deviceCode, client_id: issued.clientId,
  });
  const finished = Date.now();
  assert.equal(redemption.status, 200);
  assert.equal(typeof redemption.body.access_token, "string");
  assert.ok(redemption.body.access_token.length > 0);
  const session = await context.adapter.findOne({ model: "session",
    where: [{ field: "token", value: redemption.body.access_token }] });
  assert.ok(session, "The returned access token names a persisted session");
  const expiry = new Date(session.expiresAt).getTime();
  const remaining = redemption.body.expires_in;
  assert.ok(Number.isInteger(remaining));
  const remainingWithinObservedWindow = Math.floor((expiry - finished) / 1000) <= remaining
    && remaining <= Math.floor((expiry - started) / 1000);
  const expiryWithinConfiguredWindow = started + sessionLifetime * 1000 <= expiry
    && expiry <= finished + sessionLifetime * 1000;
  assert.equal(remainingWithinObservedWindow, true);
  assert.equal(expiryWithinConfiguredWindow, true);
  assert.equal(session.userId, owner.id);
  // Random tokens and elapsed wall time use storage relationships; other response fields stay exact.
  redemption.body = { ...redemption.body,
    access_token: { nonempty: true, storedForOwner: session.userId === owner.id },
    expires_in: { remainingWithinObservedWindow, expiryWithinConfiguredWindow },
  };
  assert.equal(await readRow(), null);
  return { input, issuance, issued, verification, claimed, approval, approved, redemption,
    events, consumed: true };
  });
}

export async function captureDeviceGrant(backend = "memory") {
  const metadata = await Bun.file(new URL("../node_modules/better-auth/package.json", import.meta.url)).json();
  assert.equal(metadata.version, "1.7.6");
  const cases = [];
  for (const input of deviceGrantInputs) cases.push(await captureCase(input, backend));
  return { version: metadata.version, sessionLifetime, cases };
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the output fixture path");
  writeFileSync(output, `${JSON.stringify(await captureDeviceGrant(), null, 2)}\n`);
}
