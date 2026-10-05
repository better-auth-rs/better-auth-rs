import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

const baseURL = "http://localhost:3000";
const metadata = {
  claims: {
    sub: "ordinary-profile-override-owner", email: "profile-override@example.test", email_verified: true,
    name: "Raw Provider Name", picture: "https://images.example.test/raw-provider.png",
    nonce: "ordinary-profile-nonce", iss: "https://accounts.google.com", aud: "client",
  },
  mappedProfile: { name: "Provider Name", image: "https://images.example.test/provider.png" },
  storedProfile: { name: "Stored Name", image: "https://images.example.test/stored.png" },
};

function profile(user) {
  return { name: user.name, image: user.image, email: user.email, emailVerified: user.emailVerified };
}

export async function captureOAuthProfileOverride() {
  const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid: "ordinary-profile-override" };
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ ...metadata.claims, iat: now, exp: now + 3600 })
    .setProtectedHeader({ alg: "RS256", kid: jwk.kid }).sign(privateKey);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    if (request.url === "https://www.googleapis.com/oauth2/v3/certs") return Response.json({ keys: [jwk] });
    assert.equal(request.url, "https://oauth2.googleapis.com/token");
    return Response.json({ id_token: token, access_token: "ordinary-profile-access", expires_in: 3600 });
  }, originalFetch);
  try {
    const rows = [];
    for (const entry of ["direct", "callback"]) {
      for (const overrideUserInfoOnSignIn of [false, true]) {
        const database = { user: [], account: [], session: [], verification: [] };
        const mapperInputs = [];
        const auth = betterAuth({
          secret: "ordinary-profile-override-secret-0123456789", baseURL,
          database: memoryAdapter(database), logger: { disabled: true }, telemetry: { enabled: false },
          socialProviders: { google: {
            clientId: "client", clientSecret: "secret", overrideUserInfoOnSignIn,
            mapProfileToUser: async raw => {
              const normalized = { ...raw };
              delete normalized.iat;
              delete normalized.exp;
              mapperInputs.push(normalized);
              return { ...metadata.mappedProfile };
            },
          } },
        });
        const cookies = new Map();
        const send = async (path, body) => {
          const headers = { Accept: body ? "application/json" : "text/html", Origin: baseURL };
          if (body) headers["Content-Type"] = "application/json";
          if (cookies.size) headers.Cookie = [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");
          const response = await auth.handler(new Request(`${baseURL}/api/auth${path}`, {
            method: body ? "POST" : "GET", headers, ...(body && { body: JSON.stringify(body) }),
          }));
          for (const header of response.headers.getSetCookie()) {
            const pair = header.split(";")[0];
            const separator = pair.indexOf("=");
            assert.ok(separator > 0);
            const name = pair.slice(0, separator);
            const value = pair.slice(separator + 1);
            if (value) cookies.set(name, value);
            else cookies.delete(name);
          }
          return response;
        };
        const directInput = { provider: "google", idToken: { token, nonce: metadata.claims.nonce } };
        const first = await send("/sign-in/social", directInput);
        const firstBody = await first.json();
        assert.equal(first.status, 200, JSON.stringify(firstBody));
        assert.equal(database.user.length, 1);
        assert.equal(database.account.length, 1);
        assert.equal(database.session.length, 1);
        assert.ok(cookies.size > 0);
        const userId = database.user[0].id;
        const accountId = database.account[0].id;
        const initialSessionId = database.session[0].id;
        await (await auth.$context).internalAdapter.updateUser(userId, metadata.storedProfile);
        const before = profile(database.user[0]);
        const statuses = [first.status];
        let response;
        let responseUser = null;
        if (entry === "callback") {
          const start = await send("/sign-in/social", {
            provider: "google", callbackURL: `${baseURL}/welcome`, disableRedirect: true,
          });
          const startBody = await start.json();
          assert.equal(start.status, 200, JSON.stringify(startBody));
          statuses.push(start.status);
          const state = new URL(startBody.url).searchParams.get("state");
          assert.ok(state);
          response = await send(`/callback/google?code=ordinary-profile-code&state=${encodeURIComponent(state)}`);
          assert.equal(response.status, 302);
          assert.equal(response.headers.get("location"), `${baseURL}/welcome`);
        } else {
          response = await send("/sign-in/social", directInput);
          const body = await response.json();
          assert.equal(response.status, 200, JSON.stringify(body));
          responseUser = profile(body.user);
        }
        statuses.push(response.status);
        const user = database.user[0];
        const account = database.account[0];
        const expectedProfile = {
          ...(entry === "callback" && overrideUserInfoOnSignIn ? metadata.mappedProfile : metadata.storedProfile),
          email: metadata.claims.email, emailVerified: true,
        };
        assert.deepEqual(profile(user), expectedProfile);
        assert.deepEqual(mapperInputs, [metadata.claims, metadata.claims]);
        assert.equal(database.user.length, 1);
        assert.equal(database.account.length, 1);
        assert.equal(database.session.length, 2);
        assert.equal(user.id, userId);
        assert.equal(account.id, accountId);
        assert.equal(account.userId, userId);
        assert.equal(account.providerId, "google");
        assert.equal(account.accountId, metadata.claims.sub);
        assert.ok(database.session.every(session => session.userId === userId));
        assert.equal(new Set(database.session.map(session => session.id)).size, 2);
        assert.ok(database.session.some(session => session.id === initialSessionId));
        if (responseUser) assert.deepEqual(responseUser, profile(user));
        rows.push({
          entry, overrideUserInfoOnSignIn, statuses, location: response.headers.get("location"),
          firstResponseUser: profile(firstBody.user), before, after: profile(user), responseUser,
          identity: {
            sameUser: user.id === userId, sameAccount: account.id === accountId,
            accountMatchesUser: account.userId === userId, provider: account.providerId, subject: account.accountId,
            userCount: database.user.length, accountCount: database.account.length, sessionCount: database.session.length,
            sessionsMatchUser: database.session.every(session => session.userId === userId),
            distinctSessions: new Set(database.session.map(session => session.id)).size === 2,
            firstSessionPreserved: database.session.some(session => session.id === initialSessionId),
          },
          mapperInputs,
        });
      }
    }
    return { metadata, rows };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  const output = process.argv[2];
  assert.ok(output, "Pass the output fixture path");
  writeFileSync(output, `${JSON.stringify(await captureOAuthProfileOverride(), null, 2)}\n`);
}
