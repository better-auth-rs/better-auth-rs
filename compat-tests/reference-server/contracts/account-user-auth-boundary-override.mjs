import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";

export const overrideScenarios = [
  { name: "social-owner-many-direct-override", route: "social", relation: "reverse-user-reference-many", many: true, overrideUserInfo: true },
  { name: "social-owner-many-callback-override", route: "social", relation: "reverse-user-reference-many", many: true, overrideUserInfo: true, callback: true },
];

export async function prepareCallbackOverride(auth, recorder, { origin, requestHeaders, idToken }) {
  const callbackURL = `${origin}/welcome`;
  const input = { provider: "google", callbackURL, disableRedirect: true };
  const start = new Request(`${origin}/api/auth/sign-in/social`, {
    method: "POST", headers: requestHeaders, body: JSON.stringify(input),
  });
  const response = await auth.handler(start);
  const body = await response.text();
  assert.equal(response.status, 200, body);
  const parsed = JSON.parse(body);
  const authorization = new URL(parsed.url);
  assert.equal(authorization.origin, "https://accounts.google.com");
  const state = authorization.searchParams.get("state");
  const challenge = authorization.searchParams.get("code_challenge");
  assert.equal(typeof state, "string");
  assert.equal(state.length, 32);
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.ok(challenge);
  const cookies = response.headers.getSetCookie();
  assert.equal(cookies.length, 1);
  const cookie = cookies[0].split(";")[0];
  assert.ok(cookie.startsWith("better-auth.oauth_state="));
  const cookieValue = cookie.slice(cookie.indexOf("=") + 1);
  assert.ok(cookieValue);
  const replacements = new Map([
    [state, "<oauth-state>"], [challenge, "<oauth-code-challenge>"], [cookieValue, "<verified-oauth-state-cookie>"],
  ]);
  const tokenResponse = { access_token: "callback-access", id_token: idToken };
  let exchanges = 0;
  recorder.exchange = async request => {
    assert.equal(request.url, "https://oauth2.googleapis.com/token");
    assert.equal(request.method, "POST");
    const fields = Object.fromEntries(new URLSearchParams(await request.text()));
    assert.equal(fields.grant_type, "authorization_code");
    assert.equal(fields.code, "account-user-auth-code");
    assert.equal(fields.redirect_uri, `${origin}/api/auth/callback/google`);
    assert.equal(typeof fields.code_verifier, "string");
    assert.equal(createHash("sha256").update(fields.code_verifier).digest("base64url"), challenge);
    replacements.set(fields.code_verifier, "<verified-oauth-code-verifier>");
    recorder.events.push({ kind: "provider.exchange", request: {
      url: request.url, method: request.method, headers: [...request.headers], body: fields,
    }, response: tokenResponse });
    exchanges += 1;
    return Response.json(tokenResponse);
  };
  return {
    request: new Request(`${origin}/api/auth/callback/google?code=account-user-auth-code&state=${encodeURIComponent(state)}`, {
      headers: { ...requestHeaders, cookie },
    }),
    replacements, callbackURL, tokenResponse, exchanges: () => exchanges,
    setup: {
      request: { url: start.url, method: start.method, headers: [...start.headers], body: input },
      response: { status: response.status, statusText: response.statusText, headers: [...response.headers], cookies, body: parsed },
    },
  };
}

export function verifyCallbackOverride({ backend, joins, before, after, response, body, events, requestWindow, callback,
  requestHeaders, idToken, secret, expiresIn, milliseconds }) {
  const admissions = events.filter(event => event.kind === "admission");
  const hooks = events.filter(event => event.kind === "hook");
  const errors = events.filter(event => event.kind === "api-error");
  const queries = events.filter(event => event.kind === "query").map(({ operation, model }) => [operation, model]);
  const userBefore = hooks.find(event => event.model === "user" && event.phase === "before");
  const userAfter = hooks.find(event => event.model === "user" && event.phase === "after");
  const sessionBefore = hooks.find(event => event.model === "session" && event.phase === "before");
  const sessionAfter = hooks.find(event => event.model === "session" && event.phase === "after");
  const dynamic = {};
  const replacements = callback.replacements;
  assert.equal(callback.exchanges(), 1);
  assert.deepEqual(after.user, before.user, "An undefined selector must not update a seeded User with a string ID");
  assert.deepEqual(after.verification, before.verification);
  assert.equal(events.filter(event => event.kind.startsWith("password.")).length, 0);
  assert.deepEqual(events.filter(event => event.kind.startsWith("provider.")).map(event => event.kind), ["provider.exchange", "provider.userInfo"]);
  assert.deepEqual(events.find(event => event.kind === "provider.userInfo").tokens, {
    tokenType: undefined, accessToken: "callback-access", refreshToken: undefined,
    accessTokenExpiresAt: undefined, refreshTokenExpiresAt: undefined, scopes: [], idToken,
    raw: callback.tokenResponse, user: undefined,
  });
  assert.equal(admissions.length, 1);
  assert.equal(admissions[0].data.user.id, undefined);
  assert.equal(Object.hasOwn(admissions[0].data.user, "id"), true);
  assert.equal(admissions[0].data.source.action, "sign-in");
  assert.equal(admissions[0].data.source.method, "oauth");
  assert.equal(admissions[0].data.source.oauth.providerId, "google");
  assert.ok(userBefore, "The callback must reach the enabled User profile override");
  assert.deepEqual(userBefore.data, {
    name: "Provider User", image: "provider-image", email: "a@account-user-auth-boundary.test", emailVerified: true,
  });
  assert.deepEqual(queries, [
    ["findMany", "account"], ...(!joins ? [["findMany", "user"]] : []),
    ["update", "account"], ["update", "user"], ...(sessionBefore ? [["create", "session"]] : []),
  ]);
  assert.deepEqual(hooks.map(({ model, operation, phase }) => [model, operation, phase]), [
    ["account", "update", "before"], ["account", "update", "after"], ["user", "update", "before"],
    ...(userAfter ? [["user", "update", "after"]] : []),
    ...(sessionBefore ? [["session", "create", "before"]] : []),
    ...(sessionAfter ? [["session", "create", "after"]] : []),
  ]);
  if (userAfter) assert.equal(userAfter.data, null);
  assert.equal(Boolean(sessionBefore), Boolean(userAfter), "A null User update preserves the selected array for session issuance");
  const updatedAccount = after.account.find(row => row.id === "account-a");
  assert.ok(updatedAccount);
  assert.deepEqual(after.account, before.account.map(row => row.id === "account-a"
    ? { ...row, idToken, accessToken: "callback-access", updatedAt: updatedAccount.updatedAt } : row));
  assert.equal(updatedAccount.userId, "user-a");
  dynamic.accountUpdatedAt = milliseconds(updatedAccount.updatedAt);
  assert.ok(dynamic.accountUpdatedAt >= requestWindow.start && dynamic.accountUpdatedAt <= requestWindow.end);
  assert.equal(milliseconds(hooks.find(event => event.model === "account" && event.phase === "after").data.updatedAt), dynamic.accountUpdatedAt);
  if (sessionBefore) {
    const issued = sessionBefore.data;
    assert.equal(issued.userId, undefined);
    assert.equal(Object.hasOwn(issued, "userId"), true);
    assert.equal(typeof issued.token, "string");
    assert.equal(issued.token.length, 32);
    replacements.set(issued.token, "<session-token>");
    dynamic.session = Object.fromEntries(["createdAt", "updatedAt", "expiresAt"].map(key => [key, milliseconds(issued[key])]));
    assert.ok(dynamic.session.createdAt >= dynamic.accountUpdatedAt && dynamic.session.createdAt <= requestWindow.end);
    assert.ok(dynamic.session.updatedAt >= dynamic.session.createdAt && dynamic.session.updatedAt <= requestWindow.end);
    const expiryOrigin = dynamic.session.expiresAt - expiresIn * 1000;
    assert.ok(expiryOrigin >= requestWindow.start && expiryOrigin <= dynamic.session.createdAt);
  }
  if (!sessionAfter) {
    assert.equal(backend, "sqlite", "The Memory adapter returns null for an unmatched undefined User ID");
    assert.equal(response.status, 500);
    assert.equal(body, "");
    assert.equal(errors.length, 1);
    assert.deepEqual(after.session, []);
    assert.ok(response.headers.getSetCookie().every(cookie => !cookie.startsWith("better-auth.session_token=")));
    return { dynamic, replacements, cookie: null };
  }
  assert.equal(backend, "memory");
  assert.equal(response.status, 302);
  assert.equal(body, "");
  assert.equal(response.headers.get("location"), callback.callbackURL);
  assert.deepEqual(errors, []);
  assert.equal(after.session.length, 1);
  const stored = after.session[0];
  assert.equal(typeof stored.id, "string");
  assert.ok(stored.id.length > 0);
  assert.equal(sessionAfter.data.id, stored.id);
  assert.equal(stored.token, sessionBefore.data.token);
  assert.equal(sessionAfter.data.token, stored.token);
  assert.equal(Object.hasOwn(stored, "userId"), false);
  assert.equal(sessionAfter.data.userId, undefined);
  assert.equal(stored.ipAddress, requestHeaders["x-forwarded-for"]);
  assert.equal(stored.userAgent, requestHeaders["user-agent"]);
  for (const key of ["createdAt", "updatedAt", "expiresAt"]) {
    assert.equal(milliseconds(stored[key]), dynamic.session[key]);
    assert.equal(milliseconds(sessionAfter.data[key]), dynamic.session[key]);
  }
  replacements.set(stored.id, "<session-id>");
  const cookies = response.headers.getSetCookie().filter(cookie => cookie.startsWith("better-auth.session_token="));
  assert.equal(cookies.length, 1);
  const separator = cookies[0].indexOf(";");
  assert.ok(separator > 0);
  const signature = createHmac("sha256", secret).update(stored.token).digest("base64");
  assert.equal(cookies[0].slice(0, separator), `better-auth.session_token=${encodeURIComponent(`${stored.token}.${signature}`)}`);
  assert.equal(cookies[0].slice(separator), `; Max-Age=${expiresIn}; Path=/; HttpOnly; SameSite=Lax`);
  return { dynamic, replacements, cookie: {
    raw: cookies[0], normalized: `better-auth.session_token=<verified-signed-session-token>${cookies[0].slice(separator)}`,
  } };
}
