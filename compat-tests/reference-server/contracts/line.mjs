import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { SignJWT } from "jose";
import { genericOAuth, line } from "better-auth/plugins/generic-oauth";

const defaults = line({ clientId: "1234567890", clientSecret: "ordinary-line-fixture-secret-012345" });
const config = Object.fromEntries(["providerId", "authorizationUrl", "tokenUrl", "userInfoUrl", "scopes"].map(key => [key, defaults[key]]));
const cases = [
  { name: "token-profile", claims: { sub: "ordinary-line-user", name: "LINE User", email: "line@example.test", picture: "https://images.test/line.png", email_verified: true, locale: "ja-JP" } },
  { name: "nullable-profile", claims: { sub: "ordinary-line-user", name: null, email: "nullable@example.test", picture: null } },
  { name: "minimal-profile", claims: { sub: "ordinary-line-user", email: "minimal@example.test" } },
  { name: "userinfo-only", userinfo: { sub: "ordinary-line-user", name: "Userinfo User", picture: "https://images.test/userinfo.png" }, mappedEmail: "application@example.test" },
];
const key = new TextEncoder().encode("ordinary-line-fixture-secret-012345");
const { betterAuth } = await import("better-auth");
const { memoryAdapter } = await import("better-auth/adapters/memory");
const results = [];
for (const input of cases) {
  const calls = [];
  const database = { user: [], account: [], session: [], verification: [] };
  let rawProfile;
  let userinfoRequests = 0;
  globalThis.fetch = async (url, init) => {
    const request = new Request(url, init);
    assert.equal(request.url, defaults.userInfoUrl);
    assert.equal(request.headers.get("authorization"), "Bearer ordinary-access");
    userinfoRequests++;
    return Response.json(input.userinfo);
  };
  const provider = line({ clientId: "1234567890", clientSecret: "ordinary-line-fixture-secret-012345", providerId: "line-jp" });
  provider.clientId = "1234567891";
  const original = provider.getUserInfo;
  provider.getUserInfo = async tokens => { calls.push("get"); return original(tokens); };
  const token = input.claims ? await new SignJWT(input.claims).setIssuer("https://access.line.me").setAudience(provider.clientId).setIssuedAt().setExpirationTime("1h").setProtectedHeader({ alg: "HS256" }).sign(key) : undefined;
  provider.getToken = async () => ({ idToken: token, accessToken: "ordinary-access" });
  provider.mapProfileToUser = async profile => {
    calls.push("map");
    rawProfile = profile;
    return { name: `Mapped ${profile.name ?? "User"}`, ...(input.mappedEmail ? { email: input.mappedEmail } : {}) };
  };
  const auth = betterAuth({ secret: "line-normal-fixture-secret-0123456789", baseURL: "https://example.test", database: memoryAdapter(database), plugins: [genericOAuth({ config: [provider] })], logger: { disabled: true }, telemetry: { enabled: false } });
  const start = await auth.handler(new Request("https://example.test/api/auth/sign-in/social", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider: "line-jp", callbackURL: "https://example.test/welcome", disableRedirect: true }) }));
  assert.equal(start.status, 200);
  const authorization = new URL((await start.json()).url);
  assert.equal(authorization.searchParams.get("client_id"), provider.clientId);
  assert.equal(authorization.searchParams.get("nonce"), null);
  assert.equal(authorization.searchParams.get("scope"), "openid profile email");
  const state = authorization.searchParams.get("state");
  const cookie = start.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  const response = await auth.handler(new Request(`https://example.test/api/auth/callback/line-jp?code=ordinary-code&state=${encodeURIComponent(state)}`, { headers: { cookie } }));
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "https://example.test/welcome");
  assert.equal(database.user.length, 1);
  assert.equal(database.account.length, 1);
  assert.equal(database.session.length, 1);
  const user = database.user[0];
  results.push({ input, status: response.status, profile: rawProfile, calls, userinfoRequests, user: { name: user.name, email: user.email, image: user.image ?? null, emailVerified: user.emailVerified, accountSubject: database.account[0].accountId } });
}
const text = JSON.stringify({ config, results }, null, 2) + "\n";
if (process.env.LINE_OUTPUT) writeFileSync(process.env.LINE_OUTPUT, text);
else assert.deepEqual(JSON.parse(text), JSON.parse(readFileSync(new URL("../../../tests/fixtures/line-1.7.6.json", import.meta.url), "utf8")));
console.log(`LINE: ${results.length} normal code-login cases passed`);
