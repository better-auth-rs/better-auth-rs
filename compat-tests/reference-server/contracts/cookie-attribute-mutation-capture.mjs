import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { createSessionStore, setSessionCookie } from "better-auth/cookies";
import { lastLoginMethod } from "better-auth/plugins";
import { serializeCookie, serializeSignedCookie } from "better-call";

const versions = { "better-auth": "1.7.6", "@better-auth/core": "1.7.6", "better-call": "1.4.0" };
for (const [name, version] of Object.entries(versions)) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}
const origin = "https://cookie-attributes.test";
const secret = "ordinary-cookie-attribute-mutation-secret-at-least-32-characters";
const domain = ".cookie-attributes.test";
const lastLoginName = "ordinary_last_login";

// Entries preserve property order and distinguish an own undefined property from an absent property.
const attributes = value => Object.entries(value).map(([key, child]) => [key,
  child === undefined ? { type: "undefined" } : child,
]);
const cookieSnapshot = cookie => ({ name: cookie.name, attributes: attributes(cookie.attributes) });

function options(secure, partitioned) {
  return {
    baseURL: origin, secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { expiresIn: 300, cookieCache: { enabled: false } },
    advanced: {
      useSecureCookies: false,
      defaultCookieAttributes: { secure, sameSite: "lax", path: "/ordinary", httpOnly: true, domain,
        ...(partitioned === undefined ? {} : { partitioned }) },
    },
  };
}

async function serializers() {
  const cases = [];
  for (const [scenario, name, secure, partitioned] of [
    ["omitted", "ordinary", false, undefined],
    ["false", "ordinary", false, false],
    ["partitioned", "ordinary", false, true],
    ["secure-partitioned", "ordinary", true, true],
    ["secure-prefix", "__Secure-ordinary", false, true],
    ["host-prefix", "__Host-ordinary", false, true],
  ]) {
    for (const mode of ["plain", "signed"]) {
      const input = { ...options(secure, partitioned).advanced.defaultCookieAttributes, maxAge: 45.5 };
      const original = attributes(input);
      const writes = [];
      for (let index = 0; index < 2; index++) {
        const before = attributes(input);
        const header = mode === "plain"
          ? serializeCookie(name, "ordinary-output-only", input)
          : await serializeSignedCookie(name, "ordinary-output-only", secret, input);
        writes.push({ before, header, after: attributes(input) });
      }
      if (scenario === "partitioned") {
        assert.ok(!writes[0].header.includes("; Secure"));
        assert.ok(writes[1].header.includes("; Secure"));
        assert.equal(input.secure, true);
      } else {
        assert.equal(writes[0].header, writes[1].header);
      }
      if (scenario === "host-prefix") {
        assert.equal(input.path, "/");
        assert.ok(Object.hasOwn(input, "domain"));
        assert.equal(input.domain, undefined);
      }
      cases.push({ scenario, mode, name, input: original, writes });
    }
  }
  return cases;
}

async function chunks() {
  const cases = [];
  for (const secure of [false, true]) {
    for (const action of ["issue", "replace", "clear"]) {
      const context = await betterAuth(options(secure, true)).$context;
      const resolved = context.createAuthCookie("ordinary", { maxAge: 45.5 });
      const before = cookieSnapshot(resolved);
      const incoming = action === "issue" ? [] : [
        [resolved.name, "old-base"], [`${resolved.name}.5`, "old-five"],
      ];
      const writes = [];
      const groups = new Map();
      const group = attrs => {
        if (!groups.has(attrs)) groups.set(attrs, groups.size);
        return groups.get(attrs);
      };
      const responseHeaders = new Headers();
      const ctx = {
        headers: new Headers(incoming.length ? { cookie: incoming.map(([name, value]) => `${name}=${value}`).join("; ") } : {}),
        context: { logger: context.logger },
        setCookie(name, value, attrs) {
          const before = attributes(attrs);
          const header = serializeCookie(name, value, attrs);
          responseHeaders.append("set-cookie", header);
          writes.push({ name, attributeGroup: group(attrs), before, header, after: attributes(attrs) });
          return header;
        },
      };
      const store = createSessionStore(resolved.name, resolved.attributes, ctx);
      const value = action === "clear" ? null : "x".repeat(8000);
      const cookies = action === "clear" ? store.clean() : store.chunk(value);
      const prepared = cookies.map(cookie => ({ name: cookie.name, valueLength: cookie.value.length,
        attributeGroup: group(cookie.attributes), attributes: attributes(cookie.attributes) }));
      const afterPrepare = cookieSnapshot(resolved);
      store.setCookies(cookies);
      const payloads = writes.filter(write => !write.header.includes("; Max-Age=0"));
      if (action !== "clear") {
        assert.equal(payloads.length, 3);
        assert.ok(payloads.every(write => write.attributeGroup === payloads[0].attributeGroup));
        assert.equal(payloads[0].header.includes("; Secure"), secure);
        assert.ok(payloads.slice(1).every(write => write.header.includes("; Secure")));
      }
      assert.ok(writes.filter(write => write.header.includes("; Max-Age=0"))
        .every(write => write.header.includes("; Secure") === secure));
      assert.deepEqual(cookieSnapshot(resolved), before);
      cases.push({ input: { secure, partitioned: true, action, incoming, valueLength: value?.length ?? 0 },
        before, prepared, afterPrepare, writes, headers: responseHeaders.getSetCookie(), after: cookieSnapshot(resolved) });
    }
  }
  return cases;
}

function traceWriters(ctx, events) {
  const setCookie = ctx.setCookie;
  const setSignedCookie = ctx.setSignedCookie;
  const capture = (writer, name, value, attrs) => ({ kind: "write", writer, name, value,
    sameAsSessionAttributes: attrs === ctx.context.authCookies.sessionToken.attributes,
    before: attributes(attrs) });
  ctx.setCookie = (name, value, attrs) => {
    const event = capture("plain", name, value, attrs);
    const header = setCookie(name, value, attrs);
    events.push({ ...event, header, after: attributes(attrs) });
    return header;
  };
  ctx.setSignedCookie = async (name, value, signingSecret, attrs) => {
    const event = capture("signed", name, value, attrs);
    const header = await setSignedCookie(name, value, signingSecret, attrs);
    events.push({ ...event, header, after: attributes(attrs) });
    return header;
  };
}

async function lastLogin() {
  const cases = [];
  for (const prefix of ["", "__Secure-", "__Host-"]) {
    for (const partitioned of [false, true]) {
      const sessionName = `${prefix}ordinary_session_token`;
      const events = [];
      const config = options(false, partitioned);
      config.advanced.cookies = { session_token: { name: sessionName } };
      const now = new Date();
      const data = {
        user: { id: "ordinary-user", name: "Ordinary", email: "ordinary@cookie-attributes.test",
          emailVerified: true, createdAt: now, updatedAt: now },
        session: { id: "ordinary-session", userId: "ordinary-user", token: "ordinary-output-only",
          expiresAt: new Date(now.getTime() + 300000), createdAt: now, updatedAt: now },
      };
      const auth = betterAuth({ ...config, plugins: [{
        id: "cookie-attribute-mutation", endpoints: {
          cookieAttributes: createAuthEndpoint("/cookie-attributes", { method: "GET" }, async ctx => {
            traceWriters(ctx, events);
            events.push({ kind: "endpoint-before", session: cookieSnapshot(ctx.context.authCookies.sessionToken) });
            ctx.setCookie("ordinary_prior", "before", { path: "/sentinel" });
            await setSessionCookie(ctx, data, false);
            events.push({ kind: "endpoint-after", session: cookieSnapshot(ctx.context.authCookies.sessionToken) });
            ctx.setCookie("ordinary_after", "after", { path: "/sentinel" });
            return ctx.json({ newSession: Boolean(ctx.context.newSession) });
          }),
        },
      }, lastLoginMethod({ cookieName: lastLoginName, maxAge: 90.5,
        customResolveMethod(ctx) {
          events.push({ kind: "resolve", path: ctx.path,
            session: cookieSnapshot(ctx.context.authCookies.sessionToken),
            headers: ctx.context.responseHeaders.getSetCookie() });
          return "email";
        },
        beforeStoreCookie(ctx, method) {
          events.push({ kind: "before-store", method,
            session: cookieSnapshot(ctx.context.authCookies.sessionToken),
            headers: ctx.context.responseHeaders.getSetCookie() });
          traceWriters(ctx, events);
          return true;
        },
      })] });
      const context = await auth.$context;
      const before = cookieSnapshot(context.authCookies.sessionToken);
      const request = new Request(`${origin}/api/auth/cookie-attributes`);
      const response = await auth.handler(request);
      const body = await response.text();
      assert.equal(response.status, 200);
      assert.deepEqual(JSON.parse(body), { newSession: true });
      const headers = response.headers.getSetCookie();
      assert.deepEqual(headers.map(header => header.slice(0, header.indexOf("="))), [
        "ordinary_prior", sessionName, "ordinary_after", lastLoginName,
      ]);
      assert.ok(!headers[3].includes("; Secure"));
      assert.ok(headers[3].includes("; Path=/ordinary"));
      assert.ok(headers[3].includes(`; Domain=${domain}`));
      assert.equal(headers[3].includes("; Partitioned"), partitioned);
      assert.equal(headers[1].includes("; Secure"), prefix !== "");
      assert.deepEqual(cookieSnapshot(context.authCookies.sessionToken), before);
      cases.push({ input: { sessionName, lastLoginName, secure: false, partitioned },
        before, request: { url: request.url, method: request.method, headers: [...request.headers], body: null },
        response: { status: response.status, statusText: response.statusText, headers: [...response.headers], cookies: headers, body },
        events, after: cookieSnapshot(context.authCookies.sessionToken) });
    }
  }
  return cases;
}

export async function captureCookieAttributeMutation() {
  return { versions, serializers: await serializers(), chunks: await chunks(), lastLogin: await lastLogin() };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the cookie attribute mutation fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureCookieAttributeMutation(), null, 2)}\n`);
}
