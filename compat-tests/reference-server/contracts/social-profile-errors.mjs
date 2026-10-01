import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { oAuthProxy } from "better-auth/plugins";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/social-http-providers-1.7.6.json", import.meta.url), "utf8"));
const baseURL = "http://figma-errors.example.test";
const tokenContract = fixture.providers.figma.tokenContract;
const cookieHeader = response => response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");
const request = (path, body, cookie) => new Request(`${baseURL}/api/auth${path}`, {
  method: body === undefined ? "GET" : "POST",
  headers: { "content-type": "application/json", origin: baseURL, ...(cookie ? { cookie } : {}) },
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});

function setup(id, custom, proxy) {
  const provider = fixture.providers[id];
  const database = { user: [], account: [], session: [], verification: [] };
  const events = [];
  let failure;
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(req) {
    if (new URL(req.url).pathname === "/token") {
      events.push("token");
      return Response.json(tokenContract.response);
    }
    events.push("profile");
    if (id === "linear") {
      assert.equal(req.method, "POST");
      assert.equal(req.headers.get("content-type"), "application/json");
      const body = await req.json();
      body.query = body.query.replace(/\s+/g, " ").trim();
      assert.deepEqual(body, provider.profileBody);
    }
    if (failure === "api-failure") return Response.json({ resultcode: "99", message: "Temporarily unavailable" });
    if (failure === "null-profile") return Response.json(null);
    if (failure === "missing-viewer") return Response.json({ data: {} });
    return failure === "http503" ? Response.json({ error: "temporarily_unavailable" }, { status: 503 }) : Response.json(id === "linear" ? { data: { viewer: provider.profile } } : provider.profile);
  } });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign((input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    assert.ok(url === provider.tokenEndpoint || url === provider.userinfoEndpoint, `Unexpected fixture URL: ${url}`);
    return originalFetch(new URL(url === provider.tokenEndpoint ? "/token" : "/profile", server.url), init);
  }, originalFetch);
  const options = {
    clientId: fixture.clientId, clientSecret: fixture.clientSecret,
    mapProfileToUser: async () => {
      events.push("map");
      if (failure === "mapper") throw new Error("Ordinary profile mapper failed");
      return {};
    },
  };
  if (custom) options.getUserInfo = async () => {
    events.push("custom");
    if (failure === "custom") throw new Error("Ordinary custom userinfo failed");
    if (failure === "api-error") throw new APIError("TOO_MANY_REQUESTS", {
      code: "PROFILE_BUSY", message: "Profile service is busy", retryAfter: 17,
    }, { "retry-after": "17", "x-profile-error": "application" });
    return { user: provider.defaultUser, data: provider.profile };
  };
  const auth = betterAuth({
    secret: "social-profile-error-contract-secret-at-least-32-characters", baseURL,
    database: memoryAdapter(database), logger: { disabled: true }, telemetry: { enabled: false },
    socialProviders: { [id]: options },
    plugins: proxy ? [oAuthProxy({ currentURL: "http://preview.example.test", productionURL: baseURL })] : [],
  });
  return {
    auth, database, events, setFailure(value) { failure = value; },
    async login() {
      const start = await auth.handler(request("/sign-in/social", { provider: id, callbackURL: `${baseURL}/welcome`, disableRedirect: true }));
      assert.equal(start.status, 200);
      const state = new URL((await start.json()).url).searchParams.get("state");
      assert.ok(state);
      if (proxy) assert.ok(state.length > 100, "proxy must wrap the ordinary OAuth state");
      return auth.handler(request(`/callback/${id}?${new URLSearchParams({ code: "ordinary-code", state })}`, undefined, cookieHeader(start)));
    },
    async close() { globalThis.fetch = originalFetch; await server.stop(true); },
  };
}

let cases = 0;
for (const id of ["figma", "polar", "slack", "naver", "linear", "atlassian", "salesforce", "kakao"]) {
  const failures = ["http503", "mapper", "custom", ...(id === "naver" ? ["api-failure"] : []), ...(id === "linear" ? ["missing-viewer"] : []), ...(["atlassian", "kakao"].includes(id) ? ["null-profile"] : [])];
  for (const proxy of [false, true]) {
    for (const failure of failures) {
      const sample = setup(id, failure === "custom", proxy);
      try {
        sample.setFailure(failure);
        const response = await sample.login();
        const missing = failure === "http503" || failure === "api-failure" || failure === "missing-viewer" || failure === "null-profile" || (["figma", "atlassian", "salesforce"].includes(id) && failure === "mapper");
        assert.equal(response.status, missing ? 302 : 500, `${id} ${failure} proxy=${proxy}`);
        assert.equal(response.headers.get("location"), missing ? `${baseURL}/api/auth/error?error=unable_to_get_user_info` : null);
        if (!missing) assert.equal(await response.text(), "");
        for (const model of ["user", "account", "session"]) assert.equal(sample.database[model].length, 0);
        assert.deepEqual(sample.events, failure === "custom" ? ["token", "custom"] : failure === "mapper" ? ["token", "profile", "map"] : ["token", "profile"]);
        cases++;
      } finally { await sample.close(); }
    }
  }
  for (const failure of failures) {
    const sample = setup(id, failure === "custom", false);
    try {
      const login = await sample.login();
      assert.equal(login.status, 302);
      assert.equal(login.headers.get("location"), `${baseURL}/welcome`);
      for (const model of ["user", "account", "session"]) assert.equal(sample.database[model].length, 1);
      sample.events.length = 0;
      sample.setFailure(failure);
      const response = await sample.auth.handler(request(`/account-info?${new URLSearchParams({ accountId: String(sample.database.account[0].id) })}`, undefined, cookieHeader(login)));
      const missing = failure === "http503" || failure === "api-failure" || failure === "missing-viewer" || failure === "null-profile" || (["figma", "atlassian", "salesforce"].includes(id) && failure === "mapper");
      assert.equal(response.status, missing ? 401 : 500);
      if (missing) assert.deepEqual(await response.json(), { code: "FAILED_TO_GET_USER_INFO", message: "Failed to get user info" });
      else assert.equal(await response.text(), "");
      for (const model of ["user", "account", "session"]) assert.equal(sample.database[model].length, 1);
      assert.deepEqual(sample.events, failure === "custom" ? ["custom"] : failure === "mapper" ? ["profile", "map"] : ["profile"]);
      cases++;
    } finally { await sample.close(); }
  }
}

for (const primaryFailure of [false, true]) {
  const events = [];
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch(req) {
    const emails = new URL(req.url).pathname === "/user/emails";
    events.push(emails ? "emails" : "profile");
    if (emails || primaryFailure) return Response.json({ error: "temporarily_unavailable" }, { status: 503 });
    return Response.json({ id: 42, login: "octocat", email: "public@example.test" });
  } });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign((input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    assert.ok(url === "https://api.github.com/user" || url === "https://api.github.com/user/emails");
    return originalFetch(new URL(new URL(url).pathname, server.url), init);
  }, originalFetch);
  try {
    const auth = betterAuth({ secret: "social-profile-error-contract-secret-at-least-32-characters", baseURL, database: memoryAdapter({ user: [], account: [], session: [], verification: [] }), logger: { disabled: true }, telemetry: { enabled: false }, socialProviders: { github: { clientId: "client", clientSecret: "secret" } } });
    const provider = (await auth.$context).socialProviders.find(value => value.id === "github");
    const result = await provider.getUserInfo({ accessToken: "ordinary-access-token" });
    if (primaryFailure) {
      assert.equal(result, null);
      assert.deepEqual(events, ["profile"]);
    } else {
      assert.equal(result.user.email, "public@example.test");
      assert.equal(result.user.emailVerified, false);
      assert.deepEqual(events, ["profile", "emails"]);
    }
    cases++;
  } finally { globalThis.fetch = originalFetch; await server.stop(true); }
}

const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwk = { ...await exportJWK(publicKey), kid: "social-profile-error-fixture" };
const token = await new SignJWT({ sub: "ordinary-profile-subject", email: "profile@example.test", name: "Profile Owner", email_verified: true, nonce: "ordinary-nonce" })
  .setProtectedHeader({ alg: "RS256", kid: jwk.kid }).setIssuer("https://accounts.google.com").setAudience("client").setIssuedAt().setExpirationTime("1h").sign(privateKey);
const jwksServer = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch() { return Response.json({ keys: [jwk] }); } });
const originalFetch = globalThis.fetch;
globalThis.fetch = Object.assign((input, init) => {
  const url = input instanceof Request ? input.url : String(input);
  assert.equal(url, "https://www.googleapis.com/oauth2/v3/certs");
  return originalFetch(jwksServer.url, init);
}, originalFetch);
try {
  for (const custom of [false, true]) {
    const database = { user: [], account: [], session: [], verification: [] };
    const events = [];
    const options = { clientId: "client", clientSecret: "secret", mapProfileToUser: async profile => {
      assert.equal(profile.sub, "ordinary-profile-subject");
      events.push("map"); throw new Error("Ordinary profile mapper failed");
    } };
    if (custom) options.getUserInfo = async () => { events.push("custom"); throw new Error("Ordinary custom userinfo failed"); };
    const auth = betterAuth({ secret: "social-profile-error-contract-secret-at-least-32-characters", baseURL, database: memoryAdapter(database), logger: { disabled: true }, telemetry: { enabled: false }, socialProviders: { google: options } });
    const response = await auth.handler(request("/sign-in/social", { provider: "google", idToken: { token, nonce: "ordinary-nonce" } }));
    assert.equal(response.status, 500);
    assert.equal(await response.text(), "");
    assert.deepEqual(events, [custom ? "custom" : "map"]);
    for (const model of ["user", "account", "session"]) assert.equal(database[model].length, 0);
    cases++;
  }
} finally { globalThis.fetch = originalFetch; await jwksServer.stop(true); }
console.log(`${cases} ordinary Social profile error contracts passed`);

let apiErrorCases = 0;
for (const id of ["figma", "polar", "slack", "naver", "linear", "atlassian", "salesforce", "kakao"]) {
  for (const endpoint of ["callback", "proxy", "account-info"]) {
    const sample = setup(id, true, endpoint === "proxy");
    try {
      let response;
      if (endpoint === "account-info") {
        const login = await sample.login();
        assert.equal(login.status, 302);
        for (const model of ["user", "account", "session"]) assert.equal(sample.database[model].length, 1);
        sample.events.length = 0;
        sample.setFailure("api-error");
        response = await sample.auth.handler(request(`/account-info?${new URLSearchParams({ accountId: String(sample.database.account[0].id) })}`, undefined, cookieHeader(login)));
      } else {
        sample.setFailure("api-error");
        response = await sample.login();
      }
      assert.equal(response.status, 429, `${id} ${endpoint}`);
      assert.deepEqual(await response.json(), { code: "PROFILE_BUSY", message: "Profile service is busy", retryAfter: 17 });
      assert.equal(response.headers.get("retry-after"), "17");
      assert.equal(response.headers.get("x-profile-error"), "application");
      assert.equal(response.headers.get("location"), null);
      for (const model of ["user", "account", "session"]) assert.equal(sample.database[model].length, endpoint === "account-info" ? 1 : 0);
      assert.deepEqual(sample.events, endpoint === "account-info" ? ["custom"] : ["token", "custom"]);
      apiErrorCases++;
    } finally { await sample.close(); }
  }
}
console.log(`${apiErrorCases} typed UserInfo API error contracts passed`);
