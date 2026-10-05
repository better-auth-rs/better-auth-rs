import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { oneTap } from "better-auth/plugins";
import { google } from "../node_modules/@better-auth/core/dist/social-providers/google.mjs";

const metadata = {
  clientId: "ordinary-google-web-client",
  additionalClientIds: ["ordinary-google-native-client"],
  explicitOneTapClientId: "ordinary-google-one-tap-client",
  clientSecret: "ordinary-google-client-secret",
  callbackURL: "http://localhost:3000/api/auth/callback/google",
  codeVerifier: "ordinary-google-client-ids-verifier-01234567890123456789",
  profile: {
    sub: "ordinary-google-owner", name: "Google Owner", email: "google-owner@example.test",
    email_verified: true, picture: "https://images.example.test/google.png", hd: "example.test",
  },
};

export async function captureGoogleClientIds() {
  const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const clientId = [metadata.clientId, ...metadata.additionalClientIds];
  const options = { clientId, clientSecret: metadata.clientSecret, hd: metadata.profile.hd };
  const configured = google(options);
  const url = await configured.createAuthorizationURL({
    state: "ordinary-state", codeVerifier: metadata.codeVerifier, redirectURI: metadata.callbackURL,
  });
  const authorization = { origin: url.origin, path: url.pathname, query: Object.fromEntries(url.searchParams) };
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid: "ordinary-google-client-ids" };
  const originalFetch = globalThis.fetch;
  let tokenResponse;
  const requests = [];
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    if (request.url === "https://www.googleapis.com/oauth2/v3/certs") return Response.json({ keys: [jwk] });
    assert.equal(request.url, "https://oauth2.googleapis.com/token");
    requests.push({
      method: request.method, contentType: request.headers.get("content-type"),
      accept: request.headers.get("accept"), authorization: request.headers.get("authorization"),
      body: Object.fromEntries(new URLSearchParams(await request.text())),
    });
    return Response.json(tokenResponse);
  }, originalFetch);
  try {
    tokenResponse = { access_token: "ordinary-access", refresh_token: "ordinary-refresh", token_type: "Bearer" };
    const code = await configured.validateAuthorizationCode({ code: "ordinary-code", codeVerifier: metadata.codeVerifier, redirectURI: metadata.callbackURL, deviceId: "ordinary-device" });
    const refresh = await configured.refreshAccessToken("ordinary-refresh");
    const grants = { rawResponse: tokenResponse, requests: [...requests], tokens: [code, refresh] };
    const flows = [];
    for (const input of [
      { mode: "direct", audience: metadata.clientId },
      { mode: "direct", audience: metadata.additionalClientIds[0] },
      { mode: "code", audience: metadata.clientId },
      { mode: "code", audience: metadata.additionalClientIds[0] },
      { mode: "oneTap", audience: metadata.additionalClientIds[0] },
      { mode: "oneTap", audience: metadata.explicitOneTapClientId, oneTapClientIds: [metadata.explicitOneTapClientId] },
    ]) {
      const now = Math.floor(Date.now() / 1000);
      const claims = { ...metadata.profile, aud: input.audience, iss: "https://accounts.google.com", nonce: "ordinary-nonce", iat: now, exp: now + 3600 };
      const token = await new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: jwk.kid }).sign(privateKey);
      tokenResponse = { id_token: token, access_token: "ordinary-access", expires_in: 3600 };
      const database = { user: [], account: [], session: [], verification: [] };
      const mapperInputs = [];
      const auth = betterAuth({
        secret: "google-client-ids-fixture-secret-0123456789", baseURL: "http://localhost:3000",
        database: memoryAdapter(database), logger: { disabled: true }, telemetry: { enabled: false },
        socialProviders: { google: { ...options, mapProfileToUser: async profile => {
          mapperInputs.push({ sub: profile.sub, aud: profile.aud, name: profile.name, hd: profile.hd });
          return { name: "Mapped Google Owner" };
        } } },
        plugins: input.mode === "oneTap" ? [oneTap(input.oneTapClientIds ? { clientId: input.oneTapClientIds } : {})] : [],
      });
      const post = (path, body) => new Request(`http://localhost:3000/api/auth${path}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      let response;
      if (input.mode === "code") {
        const start = await auth.handler(post("/sign-in/social", { provider: "google", callbackURL: "http://localhost:3000/welcome", disableRedirect: true }));
        assert.equal(start.status, 200);
        const state = new URL((await start.json()).url).searchParams.get("state");
        assert.ok(state);
        const cookie = start.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
        response = await auth.handler(new Request(`http://localhost:3000/api/auth/callback/google?code=ordinary-code&state=${encodeURIComponent(state)}`, { headers: { cookie } }));
        assert.equal(response.status, 302);
        assert.equal(response.headers.get("location"), "http://localhost:3000/welcome");
      } else {
        response = await auth.handler(input.mode === "oneTap"
          ? post("/one-tap/callback", { idToken: token })
          : post("/sign-in/social", { provider: "google", idToken: { token, nonce: "ordinary-nonce" } }));
        assert.equal(response.status, 200, await response.text());
      }
      assert.equal(database.user.length, 1);
      assert.equal(database.account.length, 1);
      assert.equal(database.session.length, 1);
      const user = database.user[0];
      flows.push({ ...input, result: {
        status: response.status, location: response.headers.get("location"),
        user: { name: user.name, email: user.email, emailVerified: user.emailVerified, image: user.image },
        account: { providerId: database.account[0].providerId, accountId: database.account[0].accountId },
        sessions: database.session.length, mapperInputs,
      } });
    }
    return JSON.parse(JSON.stringify({ version, metadata, authorization, grants, flows }));
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  if (!output) throw new Error("Provide the Google client IDs capture output path");
  writeFileSync(output, JSON.stringify(await captureGoogleClientIds(), null, 2) + "\n");
}
