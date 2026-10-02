import { createRequire } from "node:module";
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const reference = fileURLToPath(new URL("../../compat-tests/reference-server", import.meta.url));
const requireReference = createRequire(`${reference}/package.json`);
const upstream = specifier => import(pathToFileURL(requireReference.resolve(specifier)).href);
const { betterAuth } = await upstream("better-auth");
const { createAuthEndpoint } = await upstream("better-auth/api");
const { createSessionStore, deleteSessionCookie, expireCookie, setSessionCookie } = await upstream("better-auth/cookies");
const { lastLoginMethod } = await upstream("better-auth/plugins");
const { serializeCookie } = await upstream("better-call");
const { getTelemetryAuthConfig } = await upstream("@better-auth/telemetry");

export async function captureCookieExpires() {
  const secret = "ordinary-cookie-expires-evidence-secret-more-than-32-characters";
  const day = 86_400_000;
  const capturedAt = Date.now();
  const anchor = Math.floor(capturedAt / 1000) * 1000;
  const dates = {
    futureWhole: new Date(anchor + 10 * day),
    global: new Date(anchor + 10 * day + 250),
    caller: new Date(anchor + 20 * day + 250),
    named: new Date(anchor + 30 * day + 250),
    boundary: new Date(anchor + 400 * day),
    beyondQuarter: new Date(anchor + 400 * day + 250),
    beyondHttp: new Date(anchor + 401 * day + 250),
  };
  const results = {
    metadata: {
      reference,
      nodeModules: realpathSync(`${reference}/node_modules`),
      betterAuthVersion: JSON.parse(readFileSync(`${reference}/node_modules/better-auth/package.json`, "utf8")).version,
      capturedAt, serializerNow: anchor, dates,
    },
    serializers: {}, resolution: {}, chunks: {}, session: {}, lastLogin: {}, telemetry: {},
  };
  const errorShape = error => ({ name: error?.name, message: error?.message ?? String(error) });
  function observe(build) {
    try { return { ok: true, value: build() }; }
    catch (error) { return { ok: false, error: errorShape(error) }; }
  }
  function atSerializerTime(build) {
    const originalNow = Date.now;
    try { Date.now = () => anchor; return build(); }
    finally { Date.now = originalNow; }
  }
  function shape(raw) {
    const [pair, ...attributes] = raw.split("; ");
    const split = pair.indexOf("=");
    return { name: pair.slice(0, split), valueLength: pair.slice(split + 1).length, attributes, serializedLength: raw.length };
  }
  function attributeShape(attributes) {
    return {
      attributes,
      expiresOwn: Object.hasOwn(attributes, "expires"),
      expiresIsDate: attributes.expires instanceof Date,
    };
  }
  function options() {
    return {
      baseURL: "https://cookie-expires.test", secret,
      logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
      advanced: { useSecureCookies: false },
      session: { expiresIn: 300, cookieCache: { enabled: false } },
    };
  }
  async function responseShape(auth) {
    const response = await auth.handler(new Request("https://cookie-expires.test/api/auth/cookie-expires"));
    return { status: response.status, body: await response.text(), headers: response.headers.getSetCookie().map(shape) };
  }
  const now = new Date(capturedAt);
  const data = {
    user: { id: "ordinary-user", name: "Ordinary", email: "ordinary@cookie-expires.test", emailVerified: true, createdAt: now, updatedAt: now },
    session: { id: "ordinary-session", userId: "ordinary-user", token: "ordinary-output-only", expiresAt: new Date(capturedAt + 300000), createdAt: now, updatedAt: now },
  };

  for (const [name, attributes] of Object.entries({
    omitted: {}, futureWhole: { expires: dates.futureWhole }, futureMillis: { expires: dates.global },
    boundary: { expires: dates.boundary }, beyondQuarter: { expires: dates.beyondQuarter },
    maxAgeZero: { expires: dates.global, maxAge: 0 }, withMaxAge: { expires: dates.global, maxAge: 45.5 },
    bothBeyond: { expires: dates.beyondQuarter, maxAge: 34560000.25 },
  })) {
    results.serializers[name] = {
      input: attributes,
      result: atSerializerTime(() => observe(() => shape(serializeCookie("ordinary", "display", { path: "/", httpOnly: true, sameSite: "lax", ...attributes })))),
    };
  }

  for (const [name, input] of Object.entries({
    omitted: {}, global: { global: dates.global },
    caller: { global: dates.global, caller: dates.caller },
    named: { global: dates.global, caller: dates.caller, named: dates.named },
  })) {
    const config = options();
    config.advanced.defaultCookieAttributes = input.global === undefined ? {} : { expires: input.global };
    config.advanced.cookies = { ordinary: { attributes: input.named === undefined ? {} : { expires: input.named } } };
    const context = await betterAuth(config).$context;
    const caller = { maxAge: 45.5, ...(input.caller === undefined ? {} : { expires: input.caller }) };
    const resolved = context.createAuthCookie("ordinary", caller);
    results.resolution[name] = {
      input, resolved: attributeShape(resolved.attributes),
      writer: observe(() => shape(serializeCookie(resolved.name, "display", resolved.attributes))),
    };
  }

  for (const [name, expires] of Object.entries({ omitted: undefined, futureMillis: dates.global, beyondQuarter: dates.beyondQuarter })) {
    const attributes = { path: "/", httpOnly: true, sameSite: "lax", ...(expires === undefined ? {} : { expires }) };
    const events = [];
    const logger = {
      warn: (...args) => events.push({ level: "warn", args }),
      debug: (...args) => events.push({ level: "debug", args }),
    };
    const context = { headers: new Headers({ cookie: "ordinary=display; ordinary.5=display" }), context: { logger } };
    results.chunks[name] = atSerializerTime(() => ({
      input: attributes,
      emptyChunkHeader: observe(() => shape(serializeCookie("ordinary.99", "", attributes))),
      chunk: observe(() => createSessionStore("ordinary", attributes, context).chunk("x".repeat(8000)).map(cookie => ({
        ...attributeShape(cookie.attributes), header: shape(serializeCookie(cookie.name, cookie.value, cookie.attributes)),
      }))),
      clean: observe(() => createSessionStore("ordinary", attributes, context).clean().map(cookie => ({
        ...attributeShape(cookie.attributes), header: shape(serializeCookie(cookie.name, cookie.value, cookie.attributes)),
      }))),
      clear: observe(() => {
        const writes = [];
        const responseHeaders = new Headers();
        expireCookie({ responseHeaders, context: { responseHeaders }, setCookie: (cookieName, value, attrs) => writes.push(shape(serializeCookie(cookieName, value, attrs))) }, { name: "ordinary", attributes });
        return writes;
      }),
      events,
    }));
  }

  for (const [name, input] of Object.entries({
    rememberFuture: { global: dates.global, dontRemember: false },
    browserFuture: { global: dates.global, dontRemember: true },
    clearFuture: { global: dates.global, clear: true },
    tokenError: { token: dates.beyondHttp, dontRemember: false },
    markerError: { marker: dates.beyondHttp, dontRemember: true },
    clearError: { global: dates.beyondHttp, clear: true },
    deleteFuture: { global: dates.global, deleteSession: true },
    deleteSecondError: { token: dates.global, sessionData: dates.beyondHttp, deleteSession: true },
  })) {
    const config = options();
    config.advanced.defaultCookieAttributes = input.global === undefined ? {} : { expires: input.global };
    config.advanced.cookies = {
      session_token: { attributes: input.token === undefined ? {} : { expires: input.token } },
      dont_remember: { attributes: input.marker === undefined ? {} : { expires: input.marker } },
      ...(input.sessionData === undefined ? {} : { session_data: { attributes: { expires: input.sessionData } } }),
    };
    const events = [];
    const auth = betterAuth({ ...config, plugins: [{ id: "ordinary-cookie-expires", endpoints: {
      cookieExpires: createAuthEndpoint("/cookie-expires", { method: "GET" }, async ctx => {
        ctx.setCookie("ordinary-prior", "display", { path: "/" });
        events.push("prior");
        let error = null;
        try {
          if (input.deleteSession) deleteSessionCookie(ctx);
          else if (input.clear) expireCookie(ctx, ctx.context.createAuthCookie("ordinary"));
          else await setSessionCookie(ctx, data, input.dontRemember);
          events.push("writer:complete");
        } catch (caught) { error = errorShape(caught); events.push("writer:error"); }
        return ctx.json({ error, newSession: Boolean(ctx.context.newSession) });
      }),
    } }] });
    results.session[name] = { input, response: await responseShape(auth), events };
  }

  for (const [name, input] of Object.entries({
    future: { expires: dates.global, hook: "allow" },
    veto: { expires: dates.beyondHttp, hook: "veto" },
    hookError: { expires: dates.beyondHttp, hook: "error" },
    writerError: { expires: dates.beyondHttp, hook: "allow" },
  })) {
    const config = options();
    config.advanced.defaultCookieAttributes = { expires: input.expires };
    const events = [];
    config.logger = { level: "error", log: (level, message, ...args) => events.push({ kind: "log", level, message, args: args.map(value => value instanceof Error ? errorShape(value) : value) }) };
    const auth = betterAuth({ ...config,
      onAPIError: { onError: error => events.push({ kind: "api-error", ...errorShape(error) }) },
      plugins: [{ id: "ordinary-cookie-expires", endpoints: {
        cookieExpires: createAuthEndpoint("/cookie-expires", { method: "GET" }, async ctx => {
          // Isolate the after-hook writer while retaining its configured attributes.
          ctx.setCookie(ctx.context.authCookies.sessionToken.name, "ordinary-output-only", { ...ctx.context.authCookies.sessionToken.attributes, expires: undefined, maxAge: undefined });
          events.push({ kind: "endpoint-write" });
          return ctx.json({ ok: true });
        }),
      } }, lastLoginMethod({ maxAge: 90.5, customResolveMethod: () => "email", beforeStoreCookie: () => {
        events.push({ kind: "before", hook: input.hook });
        if (input.hook === "error") throw new Error("Ordinary expires beforeStoreCookie error");
        return input.hook !== "veto";
      } })],
    });
    results.lastLogin[name] = { input, response: await responseShape(auth), events };
  }

  for (const [name, attributes] of Object.entries({ omitted: {}, futureWhole: { expires: dates.futureWhole }, futureMillis: { expires: dates.global } })) {
    const config = await getTelemetryAuthConfig({ advanced: { defaultCookieAttributes: attributes } });
    results.telemetry[name] = { input: attributes, projected: attributeShape(config.advanced.cookieAttributes) };
  }

  return JSON.parse(JSON.stringify(results));
}
