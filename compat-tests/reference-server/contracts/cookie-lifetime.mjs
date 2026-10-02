import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { testUtils } from "better-auth/plugins";
import { serializeCookie } from "better-call";

const cases = {
  omitted: {},
  integer: { sessionExpiresIn: 3600 },
  fractional: { sessionExpiresIn: 3600.5 },
  subsecond: { sessionExpiresIn: 0.5 },
  global: { defaultMaxAge: 7200.5 },
  globalAndSession: { sessionExpiresIn: 3600.5, defaultMaxAge: 7200.5 },
  cookieOverride: { sessionExpiresIn: 3600.5, cookieMaxAge: 90.5 },
  cookieSubsecond: { sessionExpiresIn: 3600.5, cookieMaxAge: 0.5 },
  cookieZero: { sessionExpiresIn: 3600.5, cookieMaxAge: 0 },
  allOverrides: { sessionExpiresIn: 3600.5, defaultMaxAge: 7200.5, cookieMaxAge: 90.5 },
};
const results = {};
for (const [name, input] of Object.entries(cases)) {
  const auth = betterAuth({
    baseURL: "https://cookie-lifetime.test",
    secret: "ordinary-cookie-lifetime-fixture-secret-more-than-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    session: { expiresIn: input.sessionExpiresIn },
    advanced: {
      useSecureCookies: false,
      defaultCookieAttributes: { maxAge: input.defaultMaxAge },
      cookies: { session_token: { attributes: input.cookieMaxAge === undefined ? {} : { maxAge: input.cookieMaxAge } } },
    },
    plugins: [testUtils()],
  });
  const context = await auth.$context;
  const user = await context.test.saveUser(context.test.createUser({ email: "ordinary@cookie-lifetime.test" }));
  const now = Date.now();
  const originalNow = Date.now;
  let cookies;
  try {
    Date.now = () => now;
    cookies = await context.test.getCookies({ userId: user.id });
  } finally { Date.now = originalNow; }
  const browser = JSON.parse(JSON.stringify(cookies[0]));
  delete browser.value;
  if (browser.expires !== undefined) browser.expires -= Math.floor(now / 1000);
  const resolved = context.authCookies.sessionToken;
  const http = serializeCookie(resolved.name, "ordinary", resolved.attributes);
  const maxAge = http.split("; ").find(attribute => attribute.startsWith("Max-Age="));
  results[name] = { input, resolvedMaxAge: resolved.attributes.maxAge, browser, httpMaxAge: maxAge?.slice("Max-Age=".length) ?? null };
}
const fixture = new URL("../../../tests/fixtures/cookie-lifetime-1.7.6.json", import.meta.url);
if (process.env.COOKIE_LIFETIME_OUTPUT) {
  writeFileSync(process.env.COOKIE_LIFETIME_OUTPUT, JSON.stringify(results, null, 2) + "\n");
  console.log(`Captured ${Object.keys(results).length} ordinary cookie lifetime cases`);
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log(`${Object.keys(results).length} ordinary cookie lifetime cases match the Rust fixture`);
}
