import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { createSessionStore, expireCookie, setSessionCookie } from "better-auth/cookies";
import { lastLoginMethod } from "better-auth/plugins";
import { serializeCookie } from "better-call";

const secret = "ordinary-cookie-serialization-fixture-secret-32-characters";
const cases = {
  omitted: {}, false: { global: false }, true: { global: true },
  callerFalse: { global: true, caller: false }, callerTrue: { global: false, caller: true },
  namedFalse: { global: true, caller: true, named: false },
  namedTrue: { global: false, caller: false, named: true },
};
function shape(header) {
  const [pair, ...attributes] = header.split("; ");
  const split = pair.indexOf("=");
  return { name: pair.slice(0, split), valueLength: pair.slice(split + 1).length, attributes: attributes.sort() };
}
function shapes(headers) { return headers.map(shape).sort((a, b) => a.name.localeCompare(b.name)); }
const now = new Date();
const data = {
  user: { id: "ordinary-user", name: "Ordinary", email: "ordinary@cookie-errors.test", emailVerified: true, createdAt: now, updatedAt: now },
  session: { id: "ordinary-session", userId: "ordinary-user", token: "ordinary-output-only", expiresAt: new Date(now.getTime() + 300000), createdAt: now, updatedAt: now },
};
const results = {};
for (const [name, input] of Object.entries(cases)) {
  const named = input.named === undefined ? {} : { partitioned: input.named };
  const events = [];
  const auth = betterAuth({
    baseURL: "https://cookie-errors.test", secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { expiresIn: 300, cookieCache: { enabled: false } },
    advanced: {
      useSecureCookies: false,
      defaultCookieAttributes: { secure: true, path: "/ordinary", domain: ".cookie-errors.test", ...(input.global === undefined ? {} : { partitioned: input.global }) },
      cookies: { ordinary: { attributes: named }, session_token: { attributes: named } },
    },
    plugins: [{ id: "ordinary-cookie-contract", endpoints: {
      cookieContract: createAuthEndpoint("/cookie-contract", { method: "GET" }, async ctx => {
        await setSessionCookie(ctx, data, false);
        return ctx.json({ error: null, newSession: Boolean(ctx.context.newSession) });
      }),
    } }, lastLoginMethod({ maxAge: 90.5, customResolveMethod: () => "email", beforeStoreCookie: () => { events.push("before"); return true; } })],
  });
  const context = await auth.$context;
  const caller = { maxAge: 45.5, ...(input.caller === undefined ? {} : { partitioned: input.caller }) };
  const resolved = context.createAuthCookie("ordinary", caller);
  const plain = context.createAuthCookie("ordinary", { maxAge: 45.5 });
  const headers = new Headers({ cookie: `${resolved.name}=display; ${resolved.name}.5=display` });
  const chunkContext = { headers, context: { logger: context.logger } };
  const chunks = createSessionStore(resolved.name, resolved.attributes, chunkContext);
  const chunkHeaders = chunks.chunk("x".repeat(8000)).map(cookie => serializeCookie(cookie.name, cookie.value, cookie.attributes));
  const clearedChunks = createSessionStore(resolved.name, resolved.attributes, chunkContext).clean().map(cookie => serializeCookie(cookie.name, cookie.value, cookie.attributes));
  const cleared = [];
  const responseHeaders = new Headers();
  expireCookie({ responseHeaders, context: { responseHeaders }, setCookie: (name, value, attributes) => cleared.push(serializeCookie(name, value, attributes)) }, plain);
  const response = await auth.handler(new Request("https://cookie-errors.test/api/auth/cookie-contract"));
  results[name] = {
    input,
    resolved: shape(serializeCookie(resolved.name, "display", resolved.attributes)),
    plain: shape(serializeCookie(plain.name, "display", plain.attributes)),
    chunks: shapes(chunkHeaders), clearChunks: shapes(clearedChunks), clear: shapes(cleared),
    session: { status: response.status, body: await response.json(), events, headers: shapes(response.headers.getSetCookie()) },
  };
}
if (process.env.COOKIE_PARTITIONED_OUTPUT) {
  writeFileSync(process.env.COOKIE_PARTITIONED_OUTPUT, JSON.stringify(results, null, 2) + "\n");
  console.log(`Captured ${Object.keys(results).length} ordinary secure cookie partitioning cases`);
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(new URL("../../../tests/fixtures/cookie-partitioned-1.7.6.json", import.meta.url), "utf8")));
  console.log("Ordinary secure cookie partitioning matches the captured Rust fixture");
}
