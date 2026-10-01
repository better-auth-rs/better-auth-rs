import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { genericOAuth, microsoftEntraId } from "better-auth/plugins/generic-oauth";

const tenant = "AABBCCDD-1122-3344-5566-778899AABBCC";
const defaults = microsoftEntraId({ clientId: "client", clientSecret: "secret", tenantId: tenant });
const config = Object.fromEntries(["providerId", "discoveryUrl", "requireIdTokenVerification", "authorizationUrl", "tokenUrl", "userInfoUrl", "scopes"].map(key => [key, defaults[key]]));
const rejectedTenants = ["common", "organizations", "consumers", "", "aabbccdd112233445566778899aabbcc"];
for (const tenantId of rejectedTenants) assert.throws(() => microsoftEntraId({ clientId: "client", clientSecret: "secret", tenantId }));
const cases = [
  { name: "token-profile", claims: { oid: "entra-object", sub: "entra-subject", name: "Token User", email: "token@example.test", email_verified: true, picture: "https://images.test/token.png", department: "Operations" } },
  { name: "placeholder-name", claims: { oid: "entra-object", sub: "entra-subject", givenname: "Token", familyname: "Surname" } },
  { name: "nullable-profile", claims: { oid: "entra-object", sub: "entra-subject", name: "Nullable User", email: null, email_verified: true, picture: null } },
  { name: "graph-merge", claims: { oid: "entra-object", sub: "entra-subject", name: "Token User", email: "token@example.test", email_verified: true, picture: "https://images.test/token.png", department: "Operations" }, graph: { sub: "entra-subject", name: "Graph User", email: "graph@example.test", email_verified: false, picture: "https://images.test/graph.png", locale: "en-US" } },
  { name: "graph-fill", claims: { oid: "entra-object", sub: "entra-subject", department: "Operations" }, graph: { sub: "entra-subject", given_name: "Graph", family_name: "User", email: "graph@example.test", email_verified: true, picture: "https://images.test/graph.png", locale: "en-US" } },
  { name: "graph-http-fallback", claims: { oid: "entra-object", sub: "entra-subject", name: "Token User", email: "token@example.test", email_verified: true }, graph: { error: "temporarily_unavailable" }, graphStatus: 503 },
  { name: "unicode-name-alias", claims: { oid: "entra-object", sub: "entra-subject", given_name: "\uFEFFÉlodie", family_name: "Martin\uFEFF", email: "elodie@example.test" } },
];
const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwk = { ...await exportJWK(publicKey), kid: "entra-normal-fixture" };
const issuer = `https://login.microsoftonline.com/${tenant.toLowerCase()}/v2.0`;
const { betterAuth } = await import("better-auth");
const { memoryAdapter } = await import("better-auth/adapters/memory");
const results = [];
for (const input of cases) for (const direct of [true, false]) {
  const calls = [];
  const database = { user: [], account: [], session: [], verification: [] };
  let rawProfile;
  let token;
  let graphRequests = 0;
  globalThis.fetch = async (url, init) => {
    const request = new Request(url, init);
    if (request.url === defaults.discoveryUrl) return Response.json({ issuer, authorization_endpoint: defaults.authorizationUrl, token_endpoint: defaults.tokenUrl, userinfo_endpoint: defaults.userInfoUrl, jwks_uri: `${issuer}/keys`, id_token_signing_alg_values_supported: ["RS256"] });
    if (request.url === `${issuer}/keys`) return Response.json({ keys: [jwk] });
    if (request.url === defaults.userInfoUrl) {
      graphRequests++;
      assert.equal(request.headers.get("authorization"), "Bearer ordinary-access");
      return Response.json(input.graph, { status: input.graphStatus ?? 200 });
    }
    assert.fail(`Unexpected Entra fixture request: ${request.url}`);
  };
  const provider = microsoftEntraId({ clientId: "client", clientSecret: "secret", tenantId: tenant });
  const original = provider.getUserInfo;
  provider.getUserInfo = async tokens => { calls.push("get"); return original(tokens); };
  provider.getToken = async () => ({ idToken: token, accessToken: input.graph ? "ordinary-access" : undefined });
  provider.mapProfileToUser = async profile => {
    calls.push("map");
    const { iss, aud, exp, iat, nonce, ...data } = profile;
    rawProfile = data;
    return { name: `Mapped ${profile.name}` };
  };
  const auth = betterAuth({ secret: "entra-normal-fixture-secret-0123456789", baseURL: "https://example.test", database: memoryAdapter(database), plugins: [genericOAuth({ config: [provider] })], logger: { disabled: true }, telemetry: { enabled: false } });
  const post = body => new Request("https://example.test/api/auth/sign-in/social", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider: "microsoft-entra-id", ...body }) });
  const sign = nonce => new SignJWT({ ...input.claims, nonce }).setIssuer(issuer).setAudience("client").setIssuedAt().setExpirationTime("1h").setProtectedHeader({ alg: "RS256", kid: jwk.kid }).sign(privateKey);
  let response;
  if (direct) {
    token = await sign("ordinary-nonce");
    response = await auth.handler(post({ idToken: { token, nonce: "ordinary-nonce", accessToken: input.graph ? "ordinary-access" : undefined } }));
    assert.equal(response.status, 200, await response.text());
  } else {
    const start = await auth.handler(post({ callbackURL: "https://example.test/welcome", disableRedirect: true }));
    assert.equal(start.status, 200);
    const authorization = new URL((await start.json()).url);
    const nonce = authorization.searchParams.get("nonce");
    assert(nonce);
    token = await sign(nonce);
    const state = authorization.searchParams.get("state");
    const cookie = start.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
    response = await auth.handler(new Request(`https://example.test/api/auth/callback/microsoft-entra-id?code=ordinary-code&state=${encodeURIComponent(state)}`, { headers: { cookie } }));
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("location"), "https://example.test/welcome");
  }
  assert.equal(database.user.length, 1);
  assert.equal(database.account.length, 1);
  assert.equal(database.session.length, 1);
  const user = database.user[0];
  results.push({ input, direct, status: response.status, profile: rawProfile, calls, graphRequests, user: { name: user.name, email: user.email, image: user.image ?? null, emailVerified: user.emailVerified, accountSubject: database.account[0].accountId } });
}
const text = JSON.stringify({ config, rejectedTenants, results }, null, 2) + "\n";
if (process.env.MICROSOFT_ENTRA_OUTPUT) writeFileSync(process.env.MICROSOFT_ENTRA_OUTPUT, text);
else assert.deepEqual(JSON.parse(text), JSON.parse(readFileSync(new URL("../../../tests/fixtures/microsoft-entra-1.7.6.json", import.meta.url), "utf8")));
console.log(`Microsoft Entra ID: ${results.length} normal signed login cases passed`);
