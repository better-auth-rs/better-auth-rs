import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth, line, microsoftEntraId } from "better-auth/plugins/generic-oauth";

const baseURL = "http://localhost:3000";
const profileURL = "https://provider.example.test/userinfo";
const tokens = { accessToken: "ordinary-profile-access" };
const profile = {
  id: "ordinary-profile-subject", email: "reader@example.test", name: "Profile Reader",
  emailVerified: true, email_verified: true, image: null, picture: null,
};
const errorBody = { code: "PROFILE_BUSY", message: "Profile service is busy", retryAfter: 17 };
const errorHeaders = { "retry-after": "17", "x-profile-error": "application" };
const inputs = [
  { name: "custom-null", source: "custom", result: "null" },
  { name: "custom-success", source: "custom", result: "success" },
  { name: "custom-error", source: "custom", result: "error" },
  { name: "mapper-error", source: "custom", result: "mapper-error" },
  { name: "missing-url", source: "missing", result: "null" },
  { name: "http-null", source: "http", result: "null" },
  { name: "http-empty", source: "http", result: "empty" },
  { name: "http-error", source: "http", result: "error" },
  { name: "http-success", source: "http", result: "success" },
];
const json = value => JSON.parse(JSON.stringify(value));
const cookie = headers => headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");

function error() {
  return new APIError("TOO_MANY_REQUESTS", errorBody, errorHeaders);
}

async function responseResult(response) {
  const text = await response.text();
  return {
    status: response.status,
    location: response.headers.get("location"),
    body: text ? JSON.parse(text) : null,
    headers: Object.fromEntries(Object.keys(errorHeaders).flatMap(name => {
      const value = response.headers.get(name);
      return value === null ? [] : [[name, value]];
    })),
  };
}

export async function captureGenericProfileResults() {
  const metadata = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8"));
  assert.equal(metadata.version, "1.7.6");
  const cases = [];
  for (const input of inputs) {
    const events = [];
    const requests = [];
    const database = { user: [], account: [], session: [], verification: [] };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = Object.assign(async (resource, init) => {
      const request = new Request(resource, init);
      assert.equal(request.url, profileURL);
      events.push("http");
      requests.push({ path: new URL(request.url).pathname, method: request.method, authorization: request.headers.get("authorization") });
      if (input.result === "empty") return new Response(null, { status: 204 });
      if (input.result === "error") return Response.json({ message: "Profile service unavailable" }, { status: 503 });
      return Response.json(input.result === "null" ? null : profile);
    }, originalFetch);
    try {
      const config = {
        providerId: "generic", clientId: "ordinary-client",
        authorizationUrl: "https://provider.example.test/authorize",
        getToken: async () => { events.push("token"); return tokens; },
        mapProfileToUser: async raw => {
          events.push("map");
          assert.equal(raw.id, profile.id);
          assert.equal(raw.email, profile.email);
          if (input.result === "mapper-error") throw error();
          return { name: "Mapped Reader", email: "mapped@example.test", emailVerified: true };
        },
        accountSubject: async ({ profile: raw }) => {
          events.push("subject");
          assert.equal(raw.email, profile.email);
          return raw.id;
        },
        ...(input.source === "http" ? { userInfoUrl: profileURL } : {}),
        ...(input.source === "custom" ? { getUserInfo: async () => {
          events.push("get");
          if (input.result === "error") throw error();
          return input.result === "null" ? null : profile;
        } } : {}),
      };
      const auth = betterAuth({
        secret: "generic-profile-results-secret-at-least-32-characters", baseURL,
        database: memoryAdapter(database), logger: { disabled: true }, telemetry: { enabled: false },
        plugins: [genericOAuth({ config: [config] })],
      });
      const provider = (await auth.$context).socialProviders.find(value => value.id === "generic");
      assert.ok(provider);
      let outcome;
      try {
        const result = await provider.getUserInfo(tokens);
        outcome = result === null ? { kind: "absent" } : {
          kind: "profile", user: json(result.user), data: json(result.data),
          subject: String(await provider.accountSubject({ profile: result.data, tokens })),
        };
      } catch (cause) {
        assert.ok(cause instanceof APIError);
        outcome = { kind: "error", response: {
          status: cause.statusCode, location: null, body: cause.body,
          headers: Object.fromEntries(new Headers(cause.headers)),
        } };
      }
      const helper = { outcome, events: events.splice(0), requests: requests.splice(0) };
      const start = await auth.api.signInSocial({
        body: { provider: "generic", callbackURL: `${baseURL}/welcome`, errorCallbackURL: `${baseURL}/error`, disableRedirect: true },
        returnHeaders: true,
      });
      const state = new URL(start.response.url).searchParams.get("state");
      assert.ok(state);
      const response = await auth.handler(new Request(
        `${baseURL}/api/auth/callback/generic?${new URLSearchParams({ code: "ordinary-code", state })}`,
        { headers: { cookie: cookie(start.headers) } },
      ));
      const callback = {
        response: await responseResult(response), events: events.splice(0), requests: requests.splice(0),
        storage: {
          user: database.user.map(value => ({ email: value.email, name: value.name, emailVerified: value.emailVerified })),
          account: database.account.map(value => ({ providerId: value.providerId, accountId: value.accountId })),
          sessions: database.session.length,
        },
      };
      cases.push({ ...input, helper, callback });
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
  const entra = microsoftEntraId({ clientId: "client", clientSecret: "secret", tenantId: "11111111-1111-1111-1111-111111111111" });
  const presetAbsence = [{ name: "entra-no-token", result: await entra.getUserInfo({}) }];
  for (const result of ["null", "empty", "error"]) {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = Object.assign(async (resource, init) => {
      const request = new Request(resource, init);
      assert.equal(request.url, "https://api.line.me/oauth2/v2.1/userinfo");
      assert.equal(request.headers.get("authorization"), `Bearer ${tokens.accessToken}`);
      if (result === "empty") return new Response(null, { status: 204 });
      if (result === "error") return Response.json({ message: "Profile service unavailable" }, { status: 503 });
      return Response.json(null);
    }, originalFetch);
    try {
      presetAbsence.push({ name: `line-${result}`, result: await line({ clientId: "client", clientSecret: "secret" }).getUserInfo(tokens) });
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
  return { version: metadata.version, profile, errorBody, errorHeaders, cases, presetAbsence };
}

if (import.meta.main) {
  const output = JSON.stringify(await captureGenericProfileResults(), null, 2) + "\n";
  const outputPath = process.argv[2] ?? process.env.GENERIC_PROFILE_RESULTS_OUTPUT;
  if (outputPath) writeFileSync(outputPath, output);
  else process.stdout.write(output);
}
