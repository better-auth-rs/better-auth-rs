import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";

const reports = [];
const profile = {
  google: { sub: "google-subject", email: "owner@example.test", name: "Owner", picture: "https://images.test/owner.png", email_verified: true },
  github: { id: 123, email: "owner@example.test", name: "Owner", login: "owner", avatar_url: "https://images.test/owner.png" },
  discord: { id: "123456789", email: "owner@example.test", username: "Owner", avatar: "portrait", verified: true },
};
globalThis.fetch = async (input, init) => {
  const url = String(input);
  let body;
  if (url === "https://social-provider-options.test/capture") { reports.push(JSON.parse(init.body)); body = {}; }
  else if (url === "https://www.googleapis.com/oauth2/v3/userinfo") body = profile.google;
  else if (url === "https://api.github.com/user") body = profile.github;
  else if (url === "https://api.github.com/user/emails") body = [{ email: "owner@example.test", primary: true, verified: true }];
  else if (url === "https://discord.com/api/users/%40me") body = profile.discord;
  else assert.fail(`Unexpected request: ${url}`);
  return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
};
const { betterAuth } = await import("better-auth");
const { generateKeyPair, SignJWT } = await import("jose");
const { privateKey } = await generateKeyPair("RS256");
const googleProfileToken = await new SignJWT(profile.google).setProtectedHeader({ alg: "RS256" }).sign(privateKey);
const { genericOAuth } = await import("better-auth/plugins");
const credentials = { clientId: "client-sentinel", clientSecret: "secret-sentinel" };
const generic = () => genericOAuth({ config: [{ providerId: "generic", ...credentials, authorizationUrl: "https://provider.test/authorize", tokenUrl: "https://provider.test/token" }] });
let callbackCalls = 0;
const unused = async () => { callbackCalls++; throw new Error("Initialization invoked a provider callback"); };
const options = {
  omitted: {},
  empty: { socialProviders: {} },
  google: { socialProviders: { google: credentials } },
  github: { socialProviders: { github: credentials } },
  discord: { socialProviders: { discord: credentials } },
  ordered: { socialProviders: { discord: credentials, google: credentials, github: credentials } },
  overwritten: { socialProviders: Object.fromEntries([["google", credentials], ["github", credentials], ["google", { ...credentials, prompt: "consent" }]]) },
  explicitDefaults: { socialProviders: { google: { ...credentials, disableDefaultScope: false, disableIdTokenSignIn: false, disableImplicitSignUp: false, disableSignUp: false, overrideUserInfoOnSignIn: false, prompt: "", scope: [] } } },
  configured: { socialProviders: { google: { ...credentials, mapProfileToUser: unused, disableDefaultScope: true, disableIdTokenSignIn: true, disableImplicitSignUp: true, disableSignUp: true, getUserInfo: unused, overrideUserInfoOnSignIn: true, prompt: "consent", verifyIdToken: unused, scope: ["calendar", "email"], refreshAccessToken: unused } } },
  genericOnly: { plugins: [generic()] },
  mixed: { socialProviders: { github: credentials }, plugins: [generic()] },
};
async function initialize(extra) {
  const count = reports.length;
  const auth = betterAuth({ secret: "social-provider-options-normal-secret-0123456789", baseURL: "https://example.test", logger: { disabled: true }, telemetry: { enabled: true }, ...extra });
  const ctx = await auth.$context;
  assert.equal(reports.length, count + 1);
  assert.equal(JSON.stringify(reports[count]).includes("secret-sentinel"), false);
  assert.equal(JSON.stringify(reports[count]).includes("client-sentinel"), false);
  return { ctx, auth, config: reports[count].payload.config };
}
const results = { initialization: {}, authorization: {}, profiles: {} };
for (const [name, extra] of Object.entries(options)) {
  const { config } = await initialize(extra);
  results.initialization[name] = { socialProviders: config.socialProviders, plugins: config.plugins };
  assert.equal(callbackCalls, 0);
}
for (const id of ["google", "github", "discord"]) {
  for (const [name, test] of Object.entries({ defaults: {}, empty: { scope: [], request: [] }, merged: { scope: ["configured", "shared"], request: ["request", "shared"], prompt: "consent" }, noDefaults: { disableDefaultScope: true, scope: ["configured"], request: ["request"] }, noScopes: { disableDefaultScope: true, scope: [], request: [] } })) {
    const { request, ...configured } = test;
    const { ctx } = await initialize({ socialProviders: { [id]: { ...credentials, ...configured } } });
    const url = await ctx.socialProviders[0].createAuthorizationURL({ state: "state", codeVerifier: "normal-code-verifier-for-local-contract", redirectURI: `https://example.test/api/auth/callback/${id}`, scopes: request });
    results.authorization[`${id}-${name}`] = { scope: url.searchParams.get("scope"), prompt: url.searchParams.get("prompt") };
  }
  for (const mode of ["mapped", "partial", "custom"]) {
    const calls = [];
    const configured = { ...credentials, mapProfileToUser: async raw => { calls.push("map"); assert.equal(raw.email, "owner@example.test"); return mode === "partial" ? { locale: "zh-TW" } : { name: "Mapped", image: null, email: "mapped@example.test", emailVerified: false, locale: "zh-TW" }; } };
    if (mode === "custom") configured.getUserInfo = async () => { calls.push("get"); return { user: { name: "Custom", image: "https://images.test/custom.png", email: "custom@example.test", emailVerified: true, locale: "en" }, data: profile[id] }; };
    const { ctx } = await initialize({ socialProviders: { [id]: configured } });
    assert.deepEqual(calls, []);
    const response = await ctx.socialProviders[0].getUserInfo({ accessToken: "normal-profile-token", ...(id === "google" ? { idToken: googleProfileToken } : {}) });
    results.profiles[`${id}-${mode}`] = { user: response.user, calls };
    assert.deepEqual(calls, mode === "custom" ? ["get"] : ["map"]);
  }
}
{
  const calls = [];
  const { auth } = await initialize({ socialProviders: { google: { ...credentials, disableIdTokenSignIn: true, verifyIdToken: async () => { calls.push("verify"); return true; }, getUserInfo: async () => { calls.push("get"); return null; } } } });
  const response = await auth.handler(new Request("https://example.test/api/auth/sign-in/social", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider: "google", idToken: { token: "unused-normal-token" } }) }));
  results.idTokenDisabled = { status: response.status, code: (await response.json()).code, calls };
  assert.deepEqual(calls, []);
}
results.errors = {};
for (const mode of ["mapper", "custom"]) {
  const calls = [];
  const configured = { ...credentials, mapProfileToUser: async () => { calls.push("map"); throw new Error("profile mapper failed"); } };
  if (mode === "custom") configured.getUserInfo = async () => { calls.push("get"); throw new Error("custom user info failed"); };
  const { ctx } = await initialize({ socialProviders: { google: configured } });
  await assert.rejects(ctx.socialProviders[0].getUserInfo({ accessToken: "normal-profile-token", idToken: googleProfileToken }), error => {
    results.errors[mode] = { message: error.message, calls };
    return true;
  });
}
const fixture = new URL("../../../tests/fixtures/social-provider-options-1.7.6.json", import.meta.url);
if (process.env.SOCIAL_PROVIDER_OPTIONS_OUTPUT) {
  writeFileSync(process.env.SOCIAL_PROVIDER_OPTIONS_OUTPUT, JSON.stringify(results, null, 2) + "\n");
  console.log("Wrote 11 social init, 15 scope, 9 normal profile, and 2 callback error cases");
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log("11 social init, 15 scope, 9 normal profile, and 2 callback error cases match the Rust fixture");
}
