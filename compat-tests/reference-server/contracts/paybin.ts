import { paybin } from "../node_modules/@better-auth/core/dist/social-providers/paybin.mjs";
import { logger } from "../node_modules/@better-auth/core/dist/env/logger.mjs";
import { generateKeyPair, jwtVerify, SignJWT } from "../node_modules/jose/dist/webapi/index.js";

const normalized = (value: unknown) => JSON.parse(JSON.stringify(value));
const presence = (response: any) => response === null ? null : Object.fromEntries(
  ["name", "email", "image", "emailVerified"].map(key => [key, {
    own: Object.hasOwn(response.user, key), undefined: response.user[key] === undefined,
  }]),
);

export async function capturePaybin(issuedAt = Math.floor(Date.now() / 1000)) {
  const metadata = {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    issuer: "https://idp.paybin.io", clientId: "ordinary-client", clientSecret: "ordinary-client-secret", issuedAt,
    verifier: "ordinary-code-verifier-for-a-local-paybin-contract",
    redirectURI: "https://app.example/callback/paybin",
  };
  const options = { clientId: metadata.clientId, clientSecret: metadata.clientSecret };
  const input = { state: "ordinary-state", codeVerifier: metadata.verifier, redirectURI: metadata.redirectURI };
  const scopeCases = [];
  for (const sample of [
    { name: "default", options: {}, input: {} },
    { name: "explicit issuer", options: { issuer: metadata.issuer }, input: {} },
    { name: "empty issuer", options: { issuer: "" }, input: {} },
    { name: "custom issuer", options: { issuer: "https://login.paybin.example/tenant" }, input: {} },
    { name: "ordered scopes and hints", options: { scope: ["merchant:read", "email"], prompt: "consent" }, input: { scopes: ["wallet:read", "email"], loginHint: "owner@example.com", idTokenNonce: "ordinary-unused-nonce", additionalParams: { ordinary: "request" } } },
    { name: "disabled defaults", options: { disableDefaultScope: true, scope: ["email"] }, input: { scopes: ["profile"] } },
    { name: "empty scopes", options: { disableDefaultScope: true }, input: {} },
    { name: "configured redirect", options: { redirectURI: "https://app.example/configured-paybin" }, input: {} },
    { name: "empty redirect", options: { redirectURI: "" }, input: {} },
    { name: "authorization endpoint", options: { authorizationEndpoint: "https://login.paybin.example/authorize?ordinary=base" }, input: { additionalParams: { ordinary: "request" } } },
  ]) {
    const request = { ...input, ...sample.input };
    scopeCases.push({ ...sample, input: request, url: (await paybin({ ...options, ...sample.options }).createAuthorizationURL(request)).href });
  }
  const configurationErrors = [];
  for (const sample of [
    { name: "missing client", options: { clientId: "" }, input },
    { name: "missing secret", options: { clientSecret: "" }, input },
    { name: "missing verifier", options: {}, input: { ...input, codeVerifier: "" } },
  ]) {
    const logs: unknown[] = [], previous = logger.error;
    logger.error = (...values: unknown[]) => { logs.push(values); };
    try {
      let error;
      try { await paybin({ ...options, ...sample.options }).createAuthorizationURL(sample.input); }
      catch (caught: any) { error = { name: caught.name, message: caught.message }; }
      configurationErrors.push({ ...sample, error, logs });
    } finally { logger.error = previous; }
  }

  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const baseClaims = { iss: metadata.issuer, aud: metadata.clientId, sub: "ordinary-paybin-owner", iat: issuedAt, exp: issuedAt + 3600 };
  async function sign(profile: any) {
    const token = await new SignJWT(profile).setProtectedHeader({ alg: "RS256", kid: "ordinary-paybin" }).sign(privateKey);
    await jwtVerify(token, publicKey, { issuer: metadata.issuer, audience: metadata.clientId, algorithms: ["RS256"] });
    return token;
  }
  const profileCases = [];
  for (const sample of [
    { name: "signed default", profile: { name: "Paybin Owner", preferred_username: "ordinary-handle", email: "owner@example.com", picture: "https://images.example/paybin.png", email_verified: true }, patch: {} },
    { name: "preferred username", profile: { name: "", preferred_username: "ordinary-handle", email: "owner@example.com", email_verified: false }, patch: {} },
    { name: "omitted display", profile: { email: "owner@example.com" }, patch: {} },
    { name: "nullable fields", profile: { name: null, preferred_username: "ordinary-handle", email: null, picture: null, email_verified: null }, patch: {} },
    { name: "mapped profile", profile: { preferred_username: "ordinary-handle", email: "owner@example.com", email_verified: true }, patch: { name: "Mapped Owner", email: "mapped@example.com", image: "https://images.example/mapped.png", emailVerified: false, ordinary: "mapped value" } },
    { name: "mapped omitted email", profile: { name: "Paybin Owner", email_verified: false }, patch: { email: "mapped@example.com" } },
    { name: "mapped null metadata", profile: { name: "Paybin Owner", email: "owner@example.com", email_verified: true }, patch: { email: null, image: null, emailVerified: null } },
  ]) {
    const profile = { ...baseClaims, ...sample.profile };
    const events: string[] = [], mapped: unknown[] = [];
    const configured = paybin({ ...options, mapProfileToUser: async (raw) => {
      events.push("mapper"); mapped.push(normalized(raw)); return sample.patch;
    } });
    const response = await configured.getUserInfo({ idToken: await sign(profile) });
    events.push("returned");
    profileCases.push({ ...sample, profile, mapped, events, result: normalized(response), presence: presence(response) });
  }
  const specialCases = [];
  const customResponse = { user: { name: "Custom Owner", email: "custom@example.com", emailVerified: false }, data: { ordinary: "custom profile" } };
  for (const mode of ["missing token", "mapper error", "custom success", "custom null", "custom error"]) {
    const events: string[] = [];
    const originalError = new Error(`Ordinary Paybin ${mode}`);
    const overrides: any = { mapProfileToUser: async () => { events.push("mapper"); throw originalError; } };
    if (mode.startsWith("custom")) overrides.getUserInfo = async () => {
      events.push("custom");
      if (mode === "custom error") throw originalError;
      return mode === "custom null" ? null : customResponse;
    };
    const request = mode === "mapper error" ? { idToken: await sign({ ...baseClaims, email: "owner@example.com" }) } : {};
    let result, error;
    try { result = await paybin({ ...options, ...overrides }).getUserInfo(request); events.push("returned"); }
    catch (caught: any) { error = { name: caught.name, message: caught.message, sameError: caught === originalError }; events.push("rejected"); }
    specialCases.push({ mode, events, ...(error ? { error } : { result: normalized(result), presence: presence(result) }) });
  }

  const grants = [];
  const signedToken = await sign({ ...baseClaims, name: "Paybin Owner", email: "owner@example.com", email_verified: true });
  for (const mode of ["code", "refresh", "code 503", "refresh 503"]) {
    const requests: unknown[] = [];
    const rawResponse = { token_type: "Bearer", access_token: mode.startsWith("refresh") ? "refreshed-access" : "ordinary-access", refresh_token: mode.startsWith("refresh") ? "rotated-refresh" : "ordinary-refresh", id_token: signedToken, scope: "openid email profile" };
    const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
      const url = new URL(request.url);
      requests.push({ url: metadata.issuer + url.pathname, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), body: await request.text() });
      return Response.json(mode.endsWith("503") ? { error: "ordinary_unavailable" } : rawResponse, { status: mode.endsWith("503") ? 503 : 200 });
    } });
    try {
      const configured = paybin({ ...options, issuer: server.url.origin });
      let response, error;
      try {
        const token = mode.startsWith("code") ? await configured.validateAuthorizationCode({ code: "ordinary-code", codeVerifier: metadata.verifier, redirectURI: metadata.redirectURI, deviceId: "ordinary-unused-device" }) : await configured.refreshAccessToken("ordinary-refresh");
        response = { ...normalized(token), idToken: "<signed ID token>", ...(token.raw ? { raw: { ...token.raw, id_token: "<signed ID token>" } } : {}) };
      } catch (caught: any) { error = { status: caught.status, statusText: caught.statusText, error: caught.error }; }
      grants.push({ name: mode, rawResponse: { ...rawResponse, id_token: "<signed ID token>" }, requests, ...(error ? { error } : { response }) });
    } finally { await server.stop(true); }
  }
  const customRefreshEvents: string[] = [];
  const customTokens = { accessToken: "custom-access", refreshToken: "custom-refresh", scopes: ["custom"] };
  const refreshed = await paybin({ ...options, refreshAccessToken: async (value) => { customRefreshEvents.push(value); return customTokens; } }).refreshAccessToken("ordinary-refresh");
  return { metadata, scopeCases, configurationErrors, profileCases, specialCases, grants, customRefresh: { events: customRefreshEvents, response: normalized(refreshed), sameResponse: refreshed === customTokens } };
}

if (import.meta.main) console.log(JSON.stringify(await capturePaybin(), null, 2));
