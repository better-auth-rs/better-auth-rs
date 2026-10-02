import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { testUtils } from "better-auth/plugins";
import { serializeCookie } from "better-call";
const { setCookieCache, decodeCookieCache, setAccountCookie } = await import(new URL("./cookies/index.mjs", import.meta.resolve("better-auth")).href);
const { symmetricDecodeJWT } = await import(new URL("./crypto/jwt.mjs", import.meta.resolve("better-auth")).href);
const inputs = {
  omitted: {},
  cacheZero: { cacheMaxAge: 0 },
  fractional: { cacheMaxAge: 3600.5 },
  global: { cacheMaxAge: 3600.5, defaultMaxAge: 7200.5 },
  override: { cacheMaxAge: 3600.5, cookieMaxAge: 90.5 },
  zero: { cacheMaxAge: 3600.5, cookieMaxAge: 0 },
};
const results = {};
for (const strategy of ["compact", "jwt", "jwe"]) {
  results[strategy] = {};
  for (const [name, input] of Object.entries(inputs)) {
    const auth = betterAuth({
      database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
      baseURL: "http://cache-lifetime.test",
      secret: "ordinary-cookie-lifetime-fixture-secret-more-than-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      session: { cookieCache: { enabled: true, strategy, maxAge: input.cacheMaxAge } },
      advanced: {
        defaultCookieAttributes: { maxAge: input.defaultMaxAge },
        cookies: { session_data: { attributes: input.cookieMaxAge === undefined ? {} : { maxAge: input.cookieMaxAge } } },
      },
      plugins: [testUtils()],
    });
    const context = await auth.$context;
    const user = await context.test.saveUser(context.test.createUser({ email: "ordinary@cache-lifetime.test" }));
    const session = await context.internalAdapter.createSession(user.id);
    const cookies = [];
    const ctx = { context, headers: new Headers(), setCookie: (name, value, attributes) => cookies.push({ name, value, attributes }) };
    const now = Date.now(), originalNow = Date.now;
    try {
      Date.now = () => now;
      await setCookieCache(ctx, { session, user }, false);
      const cookie = cookies.find(cookie => cookie.name === context.authCookies.sessionData.name);
      const decoded = await decodeCookieCache(ctx, cookie.value);
      assert.ok(decoded, "ordinary newly issued cache verifies");
      const httpMaxAge = serializeCookie(cookie.name, "ordinary", cookie.attributes).split("; ").find(value => value.startsWith("Max-Age="))?.slice(8) ?? null;
      results[strategy][name] = {
        input, resolvedMaxAge: context.authCookies.sessionData.attributes.maxAge,
        expiresIn: (decoded.expiresAt - (strategy === "compact" ? now : Math.floor(now / 1000) * 1000)) / 1000,
        email: decoded.session.user.email, httpMaxAge,
      };
    } finally { Date.now = originalNow; }
  }
}
results.account = {};
for (const [name, maxAge] of Object.entries({ fractional: 3600.5, override: 90.5 })) {
  const auth = betterAuth({
      database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    baseURL: "http://cache-lifetime.test",
    secret: "ordinary-cookie-lifetime-fixture-secret-more-than-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { cookies: { account_data: { attributes: { maxAge } } } },
  });
  const context = await auth.$context;
  const cookies = [];
  const ctx = { context, headers: new Headers(), setCookie: (name, value, attributes) => cookies.push({ name, value, attributes }) };
  const before = Math.floor(Date.now() / 1000);
  await setAccountCookie(ctx, { providerId: "ordinary", accessToken: "fixture-access-token" });
  const after = Math.floor(Date.now() / 1000);
  const cookie = cookies[0];
  const decoded = await symmetricDecodeJWT(cookie.value, context.secretConfig, "better-auth-account");
  assert.ok(decoded, "ordinary newly issued account cookie decrypts");
  assert.ok(Number.isInteger(decoded.iat) && before <= decoded.iat && decoded.iat <= after);
  const expiryBase = decoded.exp - maxAge;
  assert.ok(Number.isInteger(expiryBase) && before <= expiryBase && expiryBase <= after);
  results.account[name] = { maxAge, expiresIn: maxAge, providerId: decoded.providerId };
}
const fixture = new URL("../../../tests/fixtures/cookie-cache-lifetime-1.7.6.json", import.meta.url);
if (process.env.COOKIE_CACHE_LIFETIME_OUTPUT) {
  writeFileSync(process.env.COOKIE_CACHE_LIFETIME_OUTPUT, JSON.stringify(results, null, 2) + "\n");
  console.log("Captured ordinary cookie cache lifetime cases");
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log("Ordinary cookie cache lifetime cases match the Rust fixture");
}
