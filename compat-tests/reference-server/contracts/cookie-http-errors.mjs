import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { createSessionStore, setSessionCookie } from "better-auth/cookies";
import { lastLoginMethod } from "better-auth/plugins";
import { serializeCookie, serializeSignedCookie } from "better-call";

const secret = "ordinary-cookie-serialization-fixture-secret-32-characters";
const ages = {
  omitted: undefined, zero: 0, negativeZero: -0, fractional: 0.75,
  negative: -1, boundary: 34560000, beyondFraction: 34560000.25,
  beyond: 34560001, nan: NaN, positiveInfinity: Infinity, negativeInfinity: -Infinity,
};
function shape(header) {
  const [pair, ...attributes] = header.split("; ");
  return {
    name: pair.slice(0, pair.indexOf("=")),
    maxAge: attributes.find(value => value.startsWith("Max-Age="))?.slice(8) ?? null,
  };
}
const results = { serializers: {}, chunks: {}, session: {}, lastLogin: {} };
for (const [name, maxAge] of Object.entries(ages)) {
  const attributes = { path: "/", httpOnly: true, sameSite: "lax", maxAge };
  const result = {};
  for (const [mode, build] of Object.entries({
    plain: () => serializeCookie("ordinary", "display", attributes),
    signed: () => serializeSignedCookie("ordinary", "display", secret, attributes),
  })) {
    try { const raw = await build(); result[mode] = { raw, shape: shape(raw) }; }
    catch (error) { result[mode] = { error: error.message }; }
  }
  results.serializers[name] = result;
  const warnings = [];
  const store = createSessionStore("ordinary", attributes, {
    headers: new Headers(),
    context: { logger: { warn: (...args) => warnings.push(args) } },
  });
  try { results.chunks[name] = { headers: store.chunk("display").map(cookie => shape(serializeCookie(cookie.name, cookie.value, cookie.attributes))), warnings }; }
  catch (error) { results.chunks[name] = { error: error.message, warnings }; }
}
function options() {
  return {
    baseURL: "https://cookie-errors.test", secret,
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { useSecureCookies: false },
    session: { expiresIn: 300, cookieCache: { enabled: false } },
  };
}
const now = new Date();
const data = {
  user: { id: "ordinary-user", name: "Ordinary", email: "ordinary@cookie-errors.test", emailVerified: true, createdAt: now, updatedAt: now },
  session: { id: "ordinary-session", userId: "ordinary-user", token: "ordinary-output-only", expiresAt: new Date(now.getTime() + 300000), createdAt: now, updatedAt: now },
};
for (const [name, input] of Object.entries({
  remember: { dontRemember: false },
  browser: { dontRemember: true },
  markerError: { dontRemember: true, markerAge: 34560000.25 },
  overriddenTokenAge: { dontRemember: false, tokenAge: Infinity },
  omittedTokenAge: { dontRemember: true, tokenAge: Infinity },
})) {
  const config = options();
  config.advanced.cookies = {
    session_token: { attributes: { maxAge: input.tokenAge } },
    dont_remember: { attributes: { maxAge: input.markerAge } },
  };
  const auth = betterAuth({ ...config, plugins: [{ id: "ordinary-cookie-contract", endpoints: {
    cookieContract: createAuthEndpoint("/cookie-contract", { method: "GET" }, async ctx => {
      let error = null;
      try { await setSessionCookie(ctx, data, input.dontRemember); }
      catch (caught) { error = caught.message; }
      return ctx.json({ error, newSession: Boolean(ctx.context.newSession) });
    }),
  } }] });
  const response = await auth.handler(new Request("https://cookie-errors.test/api/auth/cookie-contract"));
  results.session[name] = { status: response.status, body: await response.json(), headers: response.headers.getSetCookie().map(shape) };
}
for (const name of ["negative", "nan", "negativeInfinity", "boundary", "beyondFraction", "positiveInfinity"]) {
  const events = [];
  const config = options();
  config.advanced.cookies = { session_token: { attributes: { maxAge: 120 } } };
  const auth = betterAuth({ ...config, onAPIError: { onError: error => events.push(error.message) }, plugins: [
    { id: "ordinary-cookie-contract", endpoints: { cookieContract: createAuthEndpoint("/cookie-contract", { method: "GET" }, async ctx => {
      ctx.setCookie(ctx.context.authCookies.sessionToken.name, "ordinary-output-only", { ...ctx.context.authCookies.sessionToken.attributes, maxAge: undefined });
      return ctx.json({ ok: true });
    }) } },
    lastLoginMethod({ maxAge: ages[name], customResolveMethod: () => "email", beforeStoreCookie: () => { events.push("before"); return true; } }),
  ] });
  const response = await auth.handler(new Request("https://cookie-errors.test/api/auth/cookie-contract"));
  results.lastLogin[name] = { status: response.status, body: await response.text(), events, headers: response.headers.getSetCookie().map(shape) };
}
const output = process.env.COOKIE_HTTP_ERRORS_OUTPUT;
if (output) {
  writeFileSync(output, JSON.stringify(results, null, 2) + "\n");
  console.log("Captured ordinary cookie serialization, chunk, session-write and LastLogin configuration results");
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(new URL("../../../tests/fixtures/cookie-http-errors-1.7.6.json", import.meta.url), "utf8")));
  console.log("Ordinary cookie HTTP error contracts match the captured fixture");
}
