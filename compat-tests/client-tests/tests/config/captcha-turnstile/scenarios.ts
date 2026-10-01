import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
async function control(ctx: Context, mode?: unknown, clear = true): Promise<any[]> {
  const response = await fetch(`${ctx.baseURL}/__test/captcha/control`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ clear, ...(mode === undefined ? {} : { mode }) }) });
  expect(response.status).toBe(200); return response.json();
}
const post = (ctx: Context, headers: Record<string,string> = {}, json: unknown = {}) => ctx.rawRequest({ path: "/api/auth/sign-in/email", method: "POST", json, headers });
const token = { "x-captcha-response": "fixture-token" };
const success = { success: true, action: "login", hostname: "auth.example.test", score: 0.8 };
async function native(ctx: Context) {
  const response = await fetch(`${ctx.baseURL}/__test/captcha/native`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: ctx.uniqueEmail("captcha-native"), password: "Password123!", name: "Native" }) });
  const result = await response.json(); expect(result.status, JSON.stringify(result)).toBe(200);
  return ctx.snapshot(result);
}

export function remoteScenarios(provider: string) {
  if (provider === "turnstile") compatScenario("CAPTCHA precedes global HTTP media and JSON decoding", async ctx => {
    const observations = [];
    for (const [headers, body, status, code] of [
      [{ "content-type": "text/plain" }, "{}", 400, "MISSING_RESPONSE"],
      [{ ...token, "content-type": "text/plain" }, "{}", 415, "UNSUPPORTED_MEDIA_TYPE"],
      [{ ...token, "content-type": "application/json" }, "{", 400, "BAD_REQUEST"],
    ] as const) {
      await control(ctx, {});
      const response = await ctx.rawRequest({ path: "/api/auth/sign-up/email", method: "POST", headers, body });
      expect(response.status).toBe(status);
      expect((response.body as any).code).toBe(code);
      const events = await control(ctx, undefined, false);
      expect(events.map(event => event.phase)).toEqual(code === "MISSING_RESPONSE" ? [] : ["provider"]);
      observations.push({ response, events });
    }
    return observations;
  });
  compatScenario("CAPTCHA runs before parsing, preserves native calls, and sends the provider-specific payload", async ctx => {
    await control(ctx, {});
    const bypass = await native(ctx);
    expect(await control(ctx, undefined, false)).toEqual([]);
    const missing = await ctx.rawRequest({ path: "/api/auth/sign-in/email", method: "POST", body: "{", headers: { "content-type": "application/json" } });
    expect(missing.status).toBe(400); expect(missing.body).toEqual({ message: "Missing CAPTCHA response", code: "MISSING_RESPONSE" });
    expect(await control(ctx, undefined, false)).toEqual([]);
    const rejected = await post(ctx, token);
    expect(rejected.status).toBe(400);
    const validationEvents = await control(ctx, undefined, false);
    expect(validationEvents[0]).toMatchObject({ phase: "provider", body: { secret: "fixture-secret", response: "fixture-token" } });
    const allowed = await ctx.rawRequest({ path: "/api/auth/sign-up/email", method: "POST", headers: { ...token, "x-forwarded-for": "203.0.113.7" }, json: { email: ctx.uniqueEmail("captcha-http"), password: "Password123!", name: "HTTP" } });
    expect(allowed.status, JSON.stringify(allowed)).toBe(200);
    const session = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect((session.body as any).session.ipAddress).toBe(provider === "hcaptcha" ? "" : "203.0.113.7");
    const events = await control(ctx, undefined, false);
    expect(events.slice(-3).map(event => event.phase)).toEqual(["provider", "before", "after"]);
    const sent = events.findLast(event => event.phase === "provider");
    expect(sent.type).toBe(provider === "turnstile" ? "application/json" : "application/x-www-form-urlencoded");
    if (provider === "hcaptcha") { expect(sent.body).toHaveProperty("sitekey", "fixture-site"); expect(sent.body).not.toHaveProperty("remoteip"); }
    else expect(sent.body[provider === "captchafox" ? "remoteIp" : "remoteip"]).toBe("203.0.113.7");
    if (provider === "captchafox") expect(sent.body.sitekey).toBe("fixture-site");
    return { bypass, missing, rejected, validationEvents, allowed, session, events };
  });
  compatScenario("provider rejection, invalid data, action, hostname, and score retain their upstream error boundaries", async ctx => {
    const observations = [];
    const cases: [unknown, number][] = [
      [{ data: { success: false } }, 403], [{ data: null }, 500], [{ data: false }, 500],
      [{ text: "provider unavailable" }, 403], [{ text: "" }, 500], [{ status: 503 }, 500],
    ];
    if (provider === "turnstile" || provider === "recaptcha") cases.push(
      [{ data: { ...success, action: "other" } }, 403], [{ data: { ...success, hostname: "other.test" } }, 403],
      [{ data: { success: true, action: "login" } }, 403]);
    if (provider === "recaptcha") cases.push([{ data: { ...success, score: 0.49 } }, 403], [{ data: { ...success, score: "0.1" } }, 400], [{ data: { ...success, score: 0.5 } }, 400]);
    for (const [mode, status] of cases) {
      await control(ctx, mode); const response = await post(ctx, token); expect(response.status, JSON.stringify({ mode, response })).toBe(status);
      const events = await control(ctx, undefined, false);
      if (status !== 400) expect(events.map(event => event.phase)).toEqual(["provider"]);
      observations.push({ response, events });
    }
    return observations;
  });
  compatScenario("client IP uses configured header order, trusted hops, mapped IPv4, and IPv6 subnetting", async ctx => {
    const observations = [];
    for (const headers of [
      { "x-forwarded-for": "192.0.2.99, 203.0.113.7, 10.0.0.1" },
      { "x-forwarded-for": "2001:DB8:abcd:1234:5678::1" },
      { "x-forwarded-for": "::ffff:203.0.113.7" },
      { "x-client-ip": "203.0.113.8", "x-forwarded-for": "203.0.113.7" },
      { "x-forwarded-for": "2001:db8::192.0.2.1" },
    ]) {
      await control(ctx, {}); await post(ctx, { ...token, ...headers });
      const events = await control(ctx, undefined, false);
      observations.push(events[0]);
    }
    if (provider === "turnstile") {
      expect(observations.map(event => event.body.remoteip)).toEqual(["203.0.113.7", "2001:0db8:abcd:1230:0000:0000:0000:0000", "203.0.113.7", "203.0.113.8", "2001:0db8:0000:0000:0000:0000:0000:0000"]);
    } else if (provider === "hcaptcha") expect(observations.every(event => !("remoteip" in event.body))).toBe(true);
    else expect(observations[1].body[provider === "captchafox" ? "remoteIp" : "remoteip"]).toBe(provider === "captchafox" ? "2001:0db8:abcd:1234:5678:0000:0000:0001" : "2001:0db8:abcd:1234:0000:0000:0000:0000");
    return observations;
  });
  if (provider === "turnstile") compatScenario("remote verification has the upstream ten-second deadline", async ctx => {
    await control(ctx, { delay: 10_200 }); const response = await post(ctx, token);
    expect(response.status).toBe(500); expect(response.body).toEqual({ message: "Something went wrong", code: "UNKNOWN_ERROR" });
    const events = await control(ctx, undefined, false); expect(events.map(event => event.phase)).toEqual(["provider"]);
    return { response, events };
  }, 30_000);
}

export function botScenarios(profile: string) {
  compatScenario("BotID bypasses token headers and custom validation receives the request and verdict", async ctx => {
    await control(ctx, {}); const bypass = await native(ctx); expect(await control(ctx, undefined, false)).toEqual([]);
    const observations = [];
    for (const [verification, allow, status] of [
      [{ isBot: false }, false, 400], [{ isBot: true }, false, 403],
      [{ isBot: true, isVerifiedBot: true, verifiedBotName: "Search", verifiedBotCategory: "search" }, true, profile === "botid" ? 400 : 403],
    ] as const) {
      await control(ctx, { verification }); const response = await post(ctx, allow ? { "x-bot-allow": "yes" } : {});
      expect(response.status).toBe(status); observations.push({ response, events: await control(ctx, undefined, false) });
    }
    await control(ctx, { throw: true }); const failure = await post(ctx); expect(failure.status).toBe(500);
    return { bypass, observations, failure, events: await control(ctx, undefined, false) };
  });
  if (profile === "botid") compatScenario("BotID times out without cancelling the application callback", async ctx => {
    await control(ctx, { delay: 10_100 }); const response = await post(ctx); expect(response.status).toBe(500);
    await Bun.sleep(200); const events = await control(ctx, undefined, false);
    expect(events.map(event => event.phase)).toEqual(["check", "checked", "validate"]);
    await control(ctx, { validatorThrow: true }); const failure = await post(ctx); expect(failure.status).toBe(500);
    return { response, events, failure, failureEvents: await control(ctx, undefined, false) };
  }, 30_000);
}

export function routingScenarios(profile: string) {
  compatScenario("CAPTCHA preserves its endpoint and pre-endpoint ordering", async ctx => {
    await control(ctx, {});
    if (profile === "empty-secret") {
      const response = await post(ctx); expect(response.status).toBe(500);
      expect(await control(ctx, undefined, false)).toEqual([]); return response;
    }
    if (profile === "rate-limit") {
      const headers = { "x-forwarded-for": "203.0.113.99" };
      const first = await post(ctx, headers); expect(first.status).toBe(400);
      const second = await post(ctx, { ...headers, ...token }); expect(second.status).toBe(429);
      const noIpFirst = await post(ctx, { "x-forwarded-for": "invalid-first" }); expect(noIpFirst.status).toBe(400);
      const noIpSecond = await post(ctx, { "x-forwarded-for": "invalid-second" }); expect(noIpSecond.status).toBe(429);
      expect(await control(ctx, undefined, false)).toEqual([]); return { first, second, noIpFirst, noIpSecond };
    }
    const responses = [];
    for (const [path, status] of [["/sign-in/email",400],["/sign-in/email/nested",404],["/protected/a/b",400],["/protected-extra",400],["/literalx",404],["//sign-in/email///",400]] as const) {
      const response = await ctx.rawRequest({ path: `/api/auth${path}`, method: "GET" }); expect(response.status, path).toBe(status); responses.push(response);
    }
    expect(await control(ctx, undefined, false)).toEqual([]); return responses;
  });
}
