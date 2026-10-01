import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";

const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwk = { ...await exportJWK(publicKey), kid: "google-normal-fixture" };
const now = Math.floor(Date.now() / 1000);
const claims = { sub: "google-normal-subject", email: "google-normal@example.test", email_verified: true, name: "Verified Google User", picture: "https://images.test/verified.png", nonce: "normal-nonce", hd: "example.test", iss: "https://accounts.google.com", aud: "client", iat: now, exp: now + 3600 };
const token = await new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: jwk.kid }).sign(privateKey);
globalThis.fetch = async (input) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (url === "https://www.googleapis.com/oauth2/v3/certs") return Response.json({ keys: [jwk] });
  if (url === "https://oauth2.googleapis.com/token") return Response.json({ id_token: token, access_token: "normal-access", expires_in: 3600 });
  assert.fail(`Unexpected Google fixture request: ${url}`);
};
const { betterAuth } = await import("better-auth");
const { memoryAdapter } = await import("better-auth/adapters/memory");
const results = {};
for (const mode of ["direct", "code", "customVerifier", "customUserInfo"]) {
  const calls = [];
  const database = { user: [], account: [], session: [], verification: [] };
  const google = {
    clientId: "client", clientSecret: "secret", hd: "example.test",
    mapProfileToUser: async profile => {
      calls.push("map");
      assert.equal(profile.name, claims.name);
      assert.equal(profile.sub, claims.sub);
      return { name: "Mapped Google User" };
    },
  };
  if (mode === "customVerifier" || mode === "customUserInfo") {
    google.verifyIdToken = async (value, nonce) => {
      calls.push("verify");
      const { payload } = await jwtVerify(value, publicKey, { issuer: claims.iss, audience: "client" });
      return payload.nonce === nonce;
    };
  }
  if (mode === "customUserInfo") google.getUserInfo = async () => {
    calls.push("get");
    return { user: { name: "Configured Google User", email: claims.email, emailVerified: true }, data: claims };
  };
  const auth = betterAuth({ secret: "google-normal-fixture-secret-0123456789", baseURL: "https://example.test", database: memoryAdapter(database), socialProviders: { google }, logger: { disabled: true }, telemetry: { enabled: false } });
  const post = body => new Request("https://example.test/api/auth/sign-in/social", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (mode === "code") {
    const start = await auth.handler(post({ provider: "google", callbackURL: "https://example.test/welcome", disableRedirect: true }));
    assert.equal(start.status, 200);
    const state = new URL((await start.json()).url).searchParams.get("state");
    const cookie = start.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
    const response = await auth.handler(new Request(`https://example.test/api/auth/callback/google?code=normal-code&state=${encodeURIComponent(state)}`, { headers: { cookie } }));
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("location"), "https://example.test/welcome");
  } else {
    const response = await auth.handler(post({ provider: "google", idToken: { token, nonce: "normal-nonce" } }));
    assert.equal(response.status, 200, JSON.stringify({ mode, headers: Object.fromEntries(response.headers), body: await response.text() }));
  }
  assert.equal(database.user.length, 1);
  assert.equal(database.account.length, 1);
  const user = database.user[0];
  results[mode] = { name: user.name, image: user.image ?? null, email: user.email, emailVerified: user.emailVerified, calls, accountSubject: database.account[0].accountId };
}
const fixture = new URL("../../../tests/fixtures/google-profile-1.7.6.json", import.meta.url);
if (process.env.GOOGLE_PROFILE_OUTPUT) {
  writeFileSync(process.env.GOOGLE_PROFILE_OUTPUT, JSON.stringify(results, null, 2) + "\n");
  console.log("Wrote four normal signed Google flow cases");
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log("Four normal signed Google flow cases match the Rust fixture");
}
