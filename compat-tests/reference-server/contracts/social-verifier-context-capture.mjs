import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { testUtils } from "better-auth/plugins";
import { google } from "../node_modules/@better-auth/core/dist/social-providers/google.mjs";
import { verifyProviderIdToken } from "../node_modules/@better-auth/core/dist/oauth2/verify-id-token.mjs";

const origin = "http://social-verifier-context.test";
const secret = "ordinary-verifier-context-secret-at-least-32-characters";
const nonce = "ordinary-verifier-nonce";
const profile = {
  sub: "ordinary-verifier-subject", name: "Verifier Owner",
  email: "verifier-owner@example.test", email_verified: true,
  picture: "https://images.example.test/verifier.png",
};

async function captureCase(operation, transport, token, realProvider) {
  const events = [];
  const database = { user: [], session: [], account: [], verification: [] };
  let cookie;
  function headers(value) {
    if (value === undefined) return null;
    return [...value].sort(([a], [b]) => a.localeCompare(b)).map(([name, content]) => {
      if (name !== "cookie") return [name, content];
      assert.equal(content, cookie, "The verifier receives the owner session cookie unchanged");
      return [name, "<owner-session-cookie>"];
    });
  }
  const auth = betterAuth({
    baseURL: origin, secret, database: memoryAdapter(database),
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    plugins: [testUtils()],
    socialProviders: { google: {
      clientId: "client", clientSecret: "secret",
      async verifyIdToken(value, expectedNonce, context) {
        assert.equal(value, token, "The verifier receives the signed fixture token unchanged");
        const accepted = await verifyProviderIdToken(realProvider, value, expectedNonce);
        assert.equal(accepted, true, "The default Google verifier accepts the ordinary signed token");
        events.push({ tokenMatchesIssued: value === token, nonce: expectedNonce, accepted,
          hasContext: context !== undefined, headers: headers(context?.headers),
          request: context?.request ? {
            url: context.request.url, method: context.request.method,
            headers: headers(context.request.headers),
          } : null,
        });
        return accepted;
      },
    } },
  });
  const context = await auth.$context;
  if (operation === "standalone") {
    const provider = context.socialProviders.find(provider => provider.id === "google");
    assert.ok(provider);
    const accepted = await verifyProviderIdToken(provider, token, nonce);
    assert.equal(accepted, true);
    assert.equal(events.length, 1);
    return { operation, transport, events, result: { accepted }, stored: null };
  }
  if (operation === "link") {
    const owner = await context.test.saveUser(context.test.createUser({
      name: profile.name, email: profile.email, emailVerified: true, image: profile.picture,
    }));
    const login = await context.test.login({ userId: owner.id });
    cookie = login.headers.get("cookie");
    assert.ok(cookie);
  }
  const path = operation === "sign-in" ? "/sign-in/social" : "/link-social";
  const endpointHeaders = new Headers({ "x-verifier-label": "endpoint-label" });
  if (cookie) endpointHeaders.set("cookie", cookie);
  const body = { provider: "google", idToken: { token, nonce } };
  let response;
  if (transport === "http") {
    endpointHeaders.set("content-type", "application/json");
    endpointHeaders.set("origin", origin);
    response = await auth.handler(new Request(`${origin}/api/auth${path}?label=ordinary`, {
      method: "POST", headers: endpointHeaders, body: JSON.stringify(body),
    }));
  } else {
    const request = transport === "native-request" ? new Request(`${origin}/original-source?label=ordinary`, {
      method: "GET", headers: { accept: "application/json", "x-verifier-label": "original-label" },
    }) : undefined;
    const endpoint = operation === "sign-in" ? "signInSocial" : "linkSocialAccount";
    response = await auth.api[endpoint]({ headers: endpointHeaders, body,
      ...(request ? { request } : {}), asResponse: true });
  }
  const result = { status: response.status, body: await response.json() };
  assert.equal(result.status, 200);
  assert.equal(events.length, 1);
  assert.equal(database.user.length, 1);
  assert.equal(database.account.length, 1);
  assert.equal(database.session.length, 1);
  const user = database.user[0];
  const account = database.account[0];
  assert.equal(account.userId, user.id);
  assert.equal(account.idToken, token);
  if (operation === "sign-in") {
    const returned = result.body.user;
    assert.equal(returned.id, user.id);
    assert.equal(returned.createdAt, user.createdAt.toISOString());
    assert.equal(returned.updatedAt, user.updatedAt.toISOString());
    assert.equal(typeof result.body.token, "string");
    assert.ok(result.body.token.length > 0);
    const session = database.session.find(session => session.token === result.body.token);
    assert.ok(session);
    assert.equal(session.userId, user.id);
    // Replace only randomness whose relationship to the persisted successful result was checked.
    result.body.user = { ...returned, id: "<stored-user-id>",
      createdAt: "<stored-createdAt>", updatedAt: "<stored-updatedAt>" };
    result.body.token = { nonempty: true, storedForUser: session.userId === user.id };
  }
  return { operation, transport, events, result, stored: {
    user: { name: user.name, email: user.email, emailVerified: user.emailVerified, image: user.image },
    account: { providerId: account.providerId, accountId: account.accountId,
      belongsToUser: account.userId === user.id, idTokenMatchesIssued: account.idToken === token },
    sessions: database.session.length,
  } };
}

export async function captureSocialVerifierContext() {
  const { version } = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
  assert.equal(version, "1.7.6");
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid: "ordinary-verifier-context" };
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ ...profile, nonce, iss: "https://accounts.google.com", aud: "client", iat: now, exp: now + 3600 })
    .setProtectedHeader({ alg: "RS256", kid: jwk.kid }).sign(privateKey);
  const realProvider = google({ clientId: "client", clientSecret: "secret" });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    assert.equal(request.url, "https://www.googleapis.com/oauth2/v3/certs");
    return Response.json({ keys: [jwk] });
  }, originalFetch);
  try {
    const cases = [];
    for (const operation of ["sign-in", "link"]) {
      for (const transport of ["http", "native-headers", "native-request"]) {
        cases.push(await captureCase(operation, transport, token, realProvider));
      }
    }
    cases.push(await captureCase("standalone", null, token, realProvider));
    // The contract covers complete JSON-visible request metadata, response bodies, and the stored outcome projection.
    return JSON.parse(JSON.stringify({ version, profile, nonce, cases }));
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the Social verifier context fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureSocialVerifierContext(), null, 2)}\n`);
}
