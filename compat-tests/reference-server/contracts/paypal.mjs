import { paypal } from "../node_modules/@better-auth/core/dist/social-providers/paypal.mjs";
import { logger } from "../node_modules/@better-auth/core/dist/env/logger.mjs";
import { generateKeyPair, jwtVerify, SignJWT } from "../node_modules/jose/dist/webapi/index.js";

const metadata = {
  version: "1.7.6", clientId: "ordinary-paypal-client", clientSecret: "ordinary-paypal-secret",
  redirectURI: "http://app.example.test/api/auth/callback/paypal",
  codeVerifier: "ordinary-paypal-code-verifier-at-least-43-characters",
};
const profile = {
  user_id: "paypal-owner", sub: "paypal-owner", name: "PayPal Owner",
  given_name: "PayPal", family_name: "Owner", email: "paypal-owner@example.test",
  email_verified: true, picture: "https://images.example.test/paypal.png",
};
const codeResponse = { access_token: "ordinary-access", refresh_token: "ordinary-refresh", token_type: "Bearer", scope: "ordinary-scope" };
const refreshResponse = { access_token: "rotated-access", refresh_token: "rotated-refresh", token_type: "Bearer", scope: "refreshed-scope" };
const normalized = (value) => JSON.parse(JSON.stringify(value));
const provider = (options = {}) => paypal({ clientId: metadata.clientId, clientSecret: metadata.clientSecret, ...options });
const authInput = { state: "ordinary-state", codeVerifier: metadata.codeVerifier, redirectURI: metadata.redirectURI };
const codeInput = { code: "ordinary-code", codeVerifier: metadata.codeVerifier, redirectURI: metadata.redirectURI, deviceId: "ignored-device" };

async function withHTTP(sample, run, ordinaryError) {
  const requests = [], events = [], logs = [];
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const url = new URL(request.url), body = await request.text();
    requests.push({ path: url.pathname + url.search, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), body });
    if (url.pathname.endsWith("/token")) {
      const refresh = new URLSearchParams(body).get("grant_type") === "refresh_token";
      events.push(refresh ? "refresh" : "code");
      return Response.json(refresh ? refreshResponse : codeResponse, { status: sample.status ?? 200 });
    }
    events.push("profile"); return Response.json(sample.profile, { status: sample.status ?? 200 });
  } });
  const originalFetch = globalThis.fetch, originalError = logger.error;
  globalThis.fetch = Object.assign((input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (!["api-m.sandbox.paypal.com", "api-m.paypal.com"].includes(url.hostname)) throw new Error("Unexpected PayPal host");
    if (!["/v1/oauth2/token", "/v1/identity/oauth2/userinfo"].includes(url.pathname)) throw new Error("Unexpected PayPal path");
    events.push(url.hostname);
    return originalFetch(new URL(url.pathname + url.search, server.url), init);
  }, originalFetch);
  logger.error = (message, error) => logs.push({ message, sameError: error === ordinaryError && ordinaryError !== undefined });
  try { return await run(requests, events, logs); }
  finally { globalThis.fetch = originalFetch; logger.error = originalError; await server.stop(true); }
}

export async function capturePayPal() {
  const fixture = { metadata, profile, codeResponse, refreshResponse, scopeCases: [], configErrors: [], grants: [], profileCases: [], specialCases: [] };
  for (const [name, options, input] of [
    ["default sandbox", {}, authInput],
    ["explicit sandbox", { environment: "sandbox" }, authInput],
    ["live", { environment: "live" }, authInput],
    ["ignored scopes", { scope: ["configured"], disableDefaultScope: true }, { ...authInput, scopes: ["requested"] }],
    ["prompt and hints", { prompt: "consent" }, { ...authInput, loginHint: "owner@example.test", idTokenNonce: "ordinary-nonce" }],
    ["additional parameters", { prompt: "consent" }, { ...authInput, additionalParams: { prompt: "login", ordinary: "value" } }],
    ["configured redirect", { redirectURI: "https://app.example.test/paypal-callback" }, authInput],
    ["empty redirect", { redirectURI: "" }, authInput],
  ]) fixture.scopeCases.push({ name, options, input, url: (await provider(options).createAuthorizationURL(input)).href });
  for (const options of [{ clientId: "" }, { clientSecret: "" }]) {
    const originalError = logger.error, logs = []; logger.error = (message) => logs.push(message);
    try { await provider(options).createAuthorizationURL(authInput); }
    catch (error) { fixture.configErrors.push({ options, error: error.message, logs }); }
    finally { logger.error = originalError; }
  }
  for (const environment of ["sandbox", "live"]) for (const grant of ["code", "refresh"]) for (const status of [200, 503]) {
    const sample = { environment, grant, status, input: grant === "code" ? codeInput : "ordinary-refresh" };
    fixture.grants.push(await withHTTP(sample, async (requests, events, logs) => {
      let result, error;
      try { result = grant === "code" ? await provider({ environment }).validateAuthorizationCode(sample.input) : await provider({ environment }).refreshAccessToken(sample.input); }
      catch (caught) { error = caught.message; }
      return normalized({ ...sample, result, error, requests, events, logs });
    }));
  }
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const idToken = await new SignJWT({ sub: profile.sub }).setProtectedHeader({ alg: "RS256" })
    .setIssuer("https://ordinary-verifier.example.test").setAudience(metadata.clientId).setIssuedAt().setExpirationTime("1h").sign(privateKey);
  await jwtVerify(idToken, publicKey, { issuer: "https://ordinary-verifier.example.test", audience: metadata.clientId });
  for (const sample of [
    { name: "default", profile },
    { name: "mapped", profile, patch: { name: "Mapped PayPal Owner", email: "mapped-paypal@example.test", image: null, emailVerified: false, ordinary: "extra" } },
    { name: "nullable fields", profile: { ...profile, email: null, email_verified: null, picture: null } },
    { name: "omitted fields", profile: Object.fromEntries(Object.entries(profile).filter(([key]) => !["email", "email_verified", "picture"].includes(key))) },
    { name: "verified optional token", profile, idToken: true },
    { name: "http 503", profile, status: 503 },
    { name: "null profile", profile: null },
    { name: "missing access token", profile, missingAccess: true },
  ]) fixture.profileCases.push(await withHTTP(sample, async (requests, events, logs) => {
    let mapperProfile;
    const configured = provider({ mapProfileToUser: async (raw) => { mapperProfile = normalized(raw); events.push("map:start"); await Promise.resolve(); events.push("map:end"); return sample.patch; } });
    const result = await configured.getUserInfo({ accessToken: sample.missingAccess ? undefined : "ordinary-access", idToken: sample.idToken ? idToken : undefined }); events.push("returned");
    return normalized({ ...sample, result, mapperProfile, requests, events, logs });
  }));
  for (const mode of ["mapper error", "custom error", "custom null", "custom success", "custom refresh error", "custom refresh success"]) {
    const ordinaryError = new Error(`Ordinary PayPal ${mode}`);
    fixture.specialCases.push(await withHTTP({ profile }, async (requests, events, logs) => {
      const options = { mapProfileToUser: async () => { events.push("mapper"); throw ordinaryError; } };
      if (mode.startsWith("custom refresh")) options.refreshAccessToken = async () => { events.push("custom refresh"); if (mode.endsWith("error")) throw ordinaryError; return { accessToken: "custom-access", scopes: [] }; };
      else if (mode.startsWith("custom")) options.getUserInfo = async () => { events.push("custom"); if (mode.endsWith("error")) throw ordinaryError; return mode.endsWith("null") ? null : { user: { name: "Custom Owner", email: "custom-paypal@example.test" }, data: profile }; };
      let result, error;
      try { result = mode.startsWith("custom refresh") ? await provider(options).refreshAccessToken("ordinary-refresh") : await provider(options).getUserInfo({ accessToken: "ordinary-access" }); events.push("returned"); }
      catch (caught) { error = { message: caught.message, sameError: caught === ordinaryError }; events.push("rejected"); }
      return normalized({ mode, result, error, requests, events, logs });
    }, ordinaryError));
  }
  return fixture;
}

if (import.meta.main) process.stdout.write(JSON.stringify(await capturePayPal(), null, 2) + "\n");
