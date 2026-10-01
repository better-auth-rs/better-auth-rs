import { expect } from "bun:test";
import { createHash, createHmac } from "node:crypto";
import { OAUTH_POPUP_COMPLETE_SCRIPT, OAUTH_POPUP_SCRIPT_CSP_HASH } from "better-auth/plugins";
import { symmetricDecrypt } from "better-auth/crypto";
import { compatScenario } from "../../../support/scenario";

const origin = "https://embed.example";
const secret = "compat-test-only-key-not-real-minimum-32chars";
const cookieState = process.env.COMPAT_PROFILE === "oauth-popup-cookie";
const signed = (text: string) => encodeURIComponent(`${text}.${createHmac("sha256", secret).update(text).digest("base64")}`);
const cookieValue = (response: Response, name: string) => response.headers.getSetCookie().map(value => value.split(";")[0]).find(value => value.startsWith(`${name}=`))?.slice(name.length + 1);
const stateCookie = cookieState ? "better-auth.oauth_state" : "better-auth.state";

async function control(ctx: any, body: unknown) {
  const response = await fetch(`${ctx.baseURL}/__test/oauth-popup`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  expect(response.status).toBe(200); return response.json();
}
async function observe(response: Response) {
  const html = await response.text();
  const data = html.match(/<script type="application\/json" id="better-auth-oauth-popup">([\s\S]*?)<\/script>/)?.[1];
  const payload = data === undefined ? undefined : JSON.parse(data);
  if (payload !== undefined) {
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(html.includes(`<script>${OAUTH_POPUP_COMPLETE_SCRIPT}</script>`)).toBe(true);
    expect(`sha256-${createHash("sha256").update(OAUTH_POPUP_COMPLETE_SCRIPT).digest("base64")}`).toBe(OAUTH_POPUP_SCRIPT_CSP_HASH);
    expect(response.headers.get("content-security-policy")).toBe(`default-src 'none'; script-src '${OAUTH_POPUP_SCRIPT_CSP_HASH}'; base-uri 'none'`);
    expect(response.headers.get("cache-control")).toBe("no-store"); expect(response.headers.get("pragma")).toBe("no-cache");
  }
  return { status: response.status, location: response.headers.get("location"), payload, body: payload ? "html" : html ? JSON.parse(html) : "", cookies: response.headers.getSetCookie().map(value => ({ name: value.split("=")[0], cleared: /max-age=0(?:;|$)/i.test(value) })) };
}
const start = (ctx: any, actor: string, query: Record<string, string>) => ctx.actor(actor).fetch(`${ctx.baseURL}/api/auth/oauth-popup/start?${new URLSearchParams(query)}`, { redirect: "manual" });

compatScenario("Popup validates query, opener and callback targets before preparing OAuth state", async ctx => {
  const missing = await observe(await start(ctx, "missing", {}));
  expect(missing.status).toBe(400);
  expect(missing.body).toEqual({ code: "VALIDATION_ERROR", message: "[query.provider] Invalid input: expected string, received undefined; [query.popupOrigin] Invalid input: expected string, received undefined" });
  const untrusted = await observe(await start(ctx, "untrusted", { provider: "popup", popupOrigin: "https://evil.example" }));
  expect(untrusted.status).toBe(403); expect(untrusted.body.code).toBe("INVALID_ORIGIN");
  const failures = [];
  for (const [field, code] of [["callbackURL", "invalid_callback_url"], ["errorCallbackURL", "invalid_error_callback_url"], ["newUserCallbackURL", "invalid_new_user_callback_url"]]) {
    const result = await observe(await start(ctx, field, { provider: "popup", popupOrigin: origin, [field]: "https://evil.example/return" }));
    expect(result.payload).toEqual({ type: "better-auth:oauth-popup", targetOrigin: origin, nonce: "", error: { code, description: "Untrusted URL: https://evil.example/return" } });
    expect(result.cookies).toEqual([]); failures.push(result);
  }
  const missingProvider = await observe(await start(ctx, "provider", { provider: "missing", popupOrigin: origin }));
  expect(missingProvider.payload.error).toEqual({ code: "provider_not_found", description: "Unknown provider: missing" });
  return { missing, untrusted, failures, missingProvider };
});

compatScenario("Popup exchanges provider HTTP credentials and returns a signed bearer token with exact CSP", async ctx => {
  const nonce = "nonce</script>\u2028\u2029";
  const response = await start(ctx, "flow", { provider: "popup", popupOrigin: origin, popupNonce: nonce, callbackURL: "/done", newUserCallbackURL: "/welcome", errorCallbackURL: "/failed", scopes: "extra", requestSignUp: "true", additionalData: JSON.stringify({ extra: "kept", date: "2026-02-30T00:00:00Z", callbackURL: "https://evil.example", oauthState: "forged", serverContext: { forged: true } }) });
  expect(response.status).toBe(302);
  const url = new URL(response.headers.get("location")!); const state = url.searchParams.get("state")!;
  expect(state).toMatch(/^[A-Za-z0-9_-]{32}$/); expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  expect(url.searchParams.get("redirect_uri")).toBe(`${ctx.baseURL}/api/auth/callback/popup`);
  expect(url.searchParams.get("scope")).toBe("extra email");
  const stored = cookieState ? JSON.parse(await symmetricDecrypt({ key: secret, data: decodeURIComponent(cookieValue(response, stateCookie)!) })) : JSON.parse((await control(ctx, { state })).value);
  expect(stored).toMatchObject({ callbackURL: "/done", errorURL: "/failed", newUserURL: "/welcome", requestSignUp: true, oauthState: state, extra: "kept", date: "2026-03-02T00:00:00.000Z" });
  expect(stored.serverContext).toBeUndefined(); expect(stored.codeVerifier).toHaveLength(128);
  const cookies = response.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  const callback = await ctx.actor("flow").fetch(`${ctx.baseURL}/api/auth/callback/popup?${new URLSearchParams({ state, code: "success" })}`, { headers: { cookie: cookies }, redirect: "manual" });
  const raw = await callback.clone().text(); expect(raw).toContain("\\u003c/script>"); expect(raw).toContain("\\u2028\\u2029");
  const completion = await observe(callback);
  expect(completion.payload).toMatchObject({ type: "better-auth:oauth-popup", targetOrigin: origin, nonce, redirectTo: "/welcome" });
  expect(completion.payload.token).toBe(decodeURIComponent(cookieValue(callback, "better-auth.session_token")!));
  expect(completion.cookies).toContainEqual({ name: "better-auth.oauth_popup", cleared: true });
  const sessionResponse = await ctx.actor("bearer").fetch(`${ctx.baseURL}/api/auth/get-session`, { headers: { authorization: `Bearer ${completion.payload.token}` } });
  expect(sessionResponse.status).toBe(200); const session = await sessionResponse.json(); expect(session.user.email).toBe("popup@example.com");
  const observed = await control(ctx, { state });
  expect(observed.events).toEqual([{ event: "token", code: "success", verifierLength: 128 }, { event: "userinfo", authorization: "Bearer popup-access" }]);
  expect(observed.value).toBeNull();
  return { url: url.toString(), completion, session, events: observed.events };
});

compatScenario("Popup failure pages retain only the cookies set before the failed operation", async ctx => {
  const broken = await start(ctx, "broken", { provider: "popup-broken", popupOrigin: origin });
  const result = await observe(broken);
  expect(result.payload.error).toEqual({ code: "popup_sign_in_failed", description: "Failed to start the OAuth flow." });
  expect(result.cookies).toEqual([{ name: stateCookie, cleared: false }, { name: "better-auth.oauth_popup", cleared: false }]);
  let rejected = null;
  if (!cookieState) {
    const state = decodeURIComponent(cookieValue(broken, stateCookie)!).split(".")[0];
    expect((await control(ctx, { state })).value).toEqual(expect.any(String));
    await control(ctx, { stateFailure: true });
    rejected = await observe(await start(ctx, "failed-state", { provider: "popup", popupOrigin: origin }));
    expect(rejected.payload.error).toEqual(result.payload.error);
    expect(rejected.cookies).toEqual([{ name: stateCookie, cleared: false }]);
  }
  return { result, rejected };
});

compatScenario("Popup callback markers distinguish missing signatures, invalid payloads and completion outcomes", async ctx => {
  const marker = signed(JSON.stringify({ popupOrigin: origin, popupNonce: "bound" }));
  const cases: [string, string | null, Record<string, string>, number, boolean][] = [
    ["absent", null, { mode: "token" }, 302, false], ["bad", "invalid", { mode: "token" }, 302, false], ["empty", signed(""), { mode: "token" }, 302, false],
    ["malformed", signed("{"), { mode: "token" }, 302, true], ["null", signed("null"), { mode: "token" }, 302, true],
    ["plain", marker, { mode: "plain" }, 200, false], ["no-result", marker, {}, 302, true],
    ["error", marker, { target: "/failed?error=denied&error_description=No+access" }, 200, true],
    ["token", marker, { mode: "token" }, 200, true], ["combined", marker, { mode: "combined" }, 200, true], ["empty-object", signed("{}"), { mode: "token" }, 200, true],
  ];
  const results = [];
  for (const [name, value, query, status, clears] of cases) {
    const response = await ctx.actor(name).fetch(`${ctx.baseURL}/api/auth/oauth2/callback/probe?${new URLSearchParams(query)}`, { headers: value === null ? {} : { cookie: `better-auth.oauth_popup=${value}` }, redirect: "manual" });
    const result = await observe(response); expect(result.status).toBe(status);
    expect(result.cookies.some(cookie => cookie.name === "better-auth.oauth_popup" && cookie.cleared)).toBe(clears);
    if (name === "token") expect(result.payload.token).toBe("raw+token.signature=");
    if (name === "combined") expect(result.payload.token).toBe("first+token");
    if (name === "error") expect(result.payload.error).toEqual({ code: "denied", description: "No access" });
    if (name === "empty-object") { expect(result.payload.targetOrigin).toBeUndefined(); expect(result.payload.nonce).toBe(""); }
    results.push({ name, result });
  }
  return results;
});

compatScenario("Popup additional data follows JSON revival and enumerable entry rules", async ctx => {
  const cases: [string, unknown, Record<string, unknown>][] = [
    ["date", "2026-02-30T00:00:00Z", {}],
    ["array", ["kept", { nested: "2026-02-30T00:00:00Z" }], { "0": "kept", "1": { nested: "2026-03-02T00:00:00.000Z" } }],
    ["text", "abc", { "0": "a", "1": "b", "2": "c" }],
    ["number", 42, {}],
    ["null", null, {}],
  ];
  const results = [];
  for (const [name, input, expected] of cases) {
    const response = await start(ctx, name, { provider: "popup", popupOrigin: origin, additionalData: JSON.stringify(input) });
    expect(response.status).toBe(302);
    const state = new URL(response.headers.get("location")!).searchParams.get("state")!;
    const stored = cookieState ? JSON.parse(await symmetricDecrypt({ key: secret, data: decodeURIComponent(cookieValue(response, stateCookie)!) })) : JSON.parse((await control(ctx, { state })).value);
    const extras = Object.fromEntries(Object.entries(stored).filter(([key]) => /^\d+$/.test(key)));
    expect(extras).toEqual(expected); results.push({ name, extras });
  }
  return results;
});
