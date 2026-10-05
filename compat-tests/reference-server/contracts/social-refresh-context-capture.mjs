import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { testUtils } from "better-auth/plugins";

const origin = "http://social-refresh-context.test";
const secret = "ordinary-refresh-context-secret-at-least-32-characters";
const accountId = "ordinary-local-account";
const refreshToken = "ordinary-old-refresh";
const tokens = {
  accessToken: "ordinary-new-access", refreshToken: "ordinary-new-refresh",
  idToken: "ordinary-new-id", tokenType: "Bearer", scopes: ["openid", "email"],
};
const modes = ["http", "native-headers", "native-request", "standalone"];

async function captureCase(mode) {
  const events = [];
  let cookie;
  function headers(value) {
    if (value === undefined) return null;
    return [...value].sort(([a], [b]) => a.localeCompare(b)).map(([name, content]) => {
      if (name !== "cookie") return [name, content];
      assert.equal(content, cookie, "The callback receives the owner session cookie unchanged");
      return [name, "<owner-session-cookie>"];
    });
  }
  const auth = betterAuth({
    baseURL: origin, secret,
    database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    plugins: [testUtils()],
    socialProviders: { google: {
      clientId: "ordinary-client", clientSecret: "ordinary-secret",
      async refreshAccessToken(token, context) {
        events.push({ token, hasContext: context !== undefined,
          headers: headers(context?.headers),
          request: context?.request ? {
            url: context.request.url, method: context.request.method,
            headers: headers(context.request.headers),
          } : null,
        });
        return tokens;
      },
    } },
  });
  const context = await auth.$context;
  if (mode === "standalone") {
    const provider = context.socialProviders.find(provider => provider.id === "google");
    assert.ok(provider?.refreshAccessToken);
    const result = await provider.refreshAccessToken(refreshToken);
    assert.equal(events.length, 1);
    return { mode, events, result, stored: null };
  }
  const owner = await context.test.saveUser(context.test.createUser({
    name: "Refresh owner", email: "owner@social-refresh-context.test",
  }));
  const login = await context.test.login({ userId: owner.id });
  cookie = login.headers.get("cookie");
  assert.ok(cookie);
  await context.adapter.create({ model: "account", forceAllowId: true, data: {
    id: accountId, userId: owner.id, accountId: "ordinary-google-subject", providerId: "google",
    accessToken: "ordinary-old-access", refreshToken, idToken: "ordinary-old-id",
    scope: "openid email", createdAt: new Date("2025-01-01T00:00:00Z"),
    updatedAt: new Date("2025-01-01T00:00:00Z"),
  } });
  const endpointHeaders = new Headers({ cookie, "x-refresh-label": "endpoint-label" });
  const body = { accountId };
  let response;
  if (mode === "http") {
    endpointHeaders.set("content-type", "application/json");
    endpointHeaders.set("origin", origin);
    response = await auth.handler(new Request(`${origin}/api/auth/refresh-token?label=ordinary`, {
      method: "POST", headers: endpointHeaders, body: JSON.stringify(body),
    }));
  } else {
    const request = mode === "native-request" ? new Request(`${origin}/original-source?label=ordinary`, {
      method: "GET", headers: { "x-refresh-label": "original-label", "accept": "application/json" },
    }) : undefined;
    response = await auth.api.refreshToken({ headers: endpointHeaders, body,
      ...(request ? { request } : {}), asResponse: true });
  }
  const result = { status: response.status, headers: [...response.headers].sort(([a], [b]) => a.localeCompare(b)),
    body: await response.json() };
  assert.equal(result.status, 200);
  assert.equal(events.length, 1);
  const row = await context.adapter.findOne({ model: "account", where: [{ field: "id", value: accountId }] });
  assert.ok(row);
  assert.equal(row.userId, owner.id);
  return { mode, events, result, stored: {
    accessToken: row.accessToken, refreshToken: row.refreshToken, idToken: row.idToken,
    scope: row.scope, belongsToOwner: row.userId === owner.id,
  } };
}

export async function captureSocialRefreshContext() {
  const { version } = await Bun.file(new URL("../node_modules/better-auth/package.json", import.meta.url)).json();
  assert.equal(version, "1.7.6");
  const cases = [];
  for (const mode of modes) cases.push(await captureCase(mode));
  // Keep complete JSON-visible results. Only the verified owner cookie contains normalized randomness.
  return JSON.parse(JSON.stringify({ version, cases }));
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the Social refresh context fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureSocialRefreshContext(), null, 2)}\n`);
}
