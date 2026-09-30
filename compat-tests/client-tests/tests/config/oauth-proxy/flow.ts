import { expect } from "bun:test";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { compatScenario } from "../../../support/scenario";
import { control } from "../../../support/oidc";
import { TS_BASE_URL, RUST_BASE_URL } from "../../../support/config";

const secret = "compat-test-only-key-not-real-minimum-32chars";
const decode = async (data: string) => JSON.parse(await symmetricDecrypt({ key: secret, data }));
const encode = (data: unknown) => symmetricEncrypt({ key: secret, data: JSON.stringify(data) });

export function cookies(response: Response, previous = "") {
  const jar = new Map(previous.split("; ").filter(Boolean).map(cookie => cookie.split(/=(.*)/s).slice(0, 2) as [string, string]));
  for (const cookie of response.headers.getSetCookie()) {
    const [pair, ...attributes] = cookie.split(";");
    const [name, value] = pair.split(/=(.*)/s);
    if (attributes.some(attribute => /^\s*max-age=0$/i.test(attribute))) jar.delete(name);
    else jar.set(name, value);
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

export async function start(ctx: any, link = false) {
  const peer = ctx.baseURL === TS_BASE_URL ? RUST_BASE_URL : TS_BASE_URL;
  await fetch(`${peer}/__test/reset-state`, { method: "POST" });
  const before = await fetch(`${peer}/__test/oauth-proxy/stats`).then(response => response.json());
  const initiation = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/${link ? "link-social" : "sign-in/social"}`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ provider: "google", callbackURL: "/return", newUserCallbackURL: "/welcome", disableRedirect: true }),
  });
  expect(initiation.status).toBe(200);
  const body = await initiation.json();
  const authorization = new URL(body.url);
  expect(authorization.searchParams.get("redirect_uri")).toBe("https://production.example.com/api/auth/callback/google");
  const state = await decode(authorization.searchParams.get("state")!);
  expect(state.isOAuthProxy).toBe(true);
  expect(state.state).toEqual(expect.any(String));
  const plaintext = await decode(state.stateCookie);
  expect(plaintext.oauthState).toBe(state.state);
  expect(plaintext.codeVerifier).toEqual(expect.any(String));
  expect(new URL(plaintext.callbackURL).origin).toBe(ctx.baseURL);
  const production = await fetch(`${peer}/api/auth/callback/google?${new URLSearchParams({ state: authorization.searchParams.get("state")!, code: "compat-code" })}`, { redirect: "manual" });
  expect(production.status).toBe(302);
  expect(production.headers.getSetCookie()).toHaveLength(0);
  const after = await fetch(`${peer}/__test/oauth-proxy/stats`).then(response => response.json());
  expect(after).toEqual(before);
  const completion = new URL(production.headers.get("location")!);
  expect(completion.origin).toBe(ctx.baseURL);
  const profile = await decode(completion.searchParams.get("profile")!);
  expect(profile.state).toBe(state.state);
  expect(profile.account.providerId).toBe("google");
  expect(profile.account.accountId).toBe("google-account-id");
  expect(profile.userInfo.emailVerified).toBe(true);
  expect(profile.callbackURL).toBe("/return");
  return { completion, profile, cookie: cookies(initiation), productionUnchanged: after };
}

export function registerProxyScenarios(cookieState = false) {
  compatScenario("OAuth proxy exchanges real OIDC tokens across runtimes", async ctx => {
    const peer = ctx.baseURL === TS_BASE_URL ? RUST_BASE_URL : TS_BASE_URL;
    await fetch(`${peer}/__test/reset-state`, { method: "POST" });
    const identity = { email: ctx.uniqueEmail("proxy-oidc"), sub: ctx.uniqueToken("proxy-oidc-subject") };
    await control("configure", { ...identity, mode: "valid" });
    const initiation = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/sign-in/social`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider: "oidc", callbackURL: "/oidc-return", disableRedirect: true }),
    });
    expect(initiation.status).toBe(200);
    const authorization = new URL((await initiation.json()).url);
    expect(authorization.searchParams.get("nonce")).toBeTruthy();
    expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
    const issued = await fetch(authorization, { redirect: "manual" });
    expect(issued.status).toBe(302);
    const callback = new URL(issued.headers.get("location")!);
    expect(callback.origin).toBe("https://production.example.com");
    const production = await fetch(`${peer}${callback.pathname}${callback.search}`, { redirect: "manual" });
    expect(production.status).toBe(302);
    const completion = new URL(production.headers.get("location")!);
    expect(completion.origin).toBe(ctx.baseURL);
    expect(completion.searchParams.has("profile")).toBe(true);
    const response = await fetch(completion, { headers: { cookie: cookies(initiation) }, redirect: "manual" });
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/oidc-return");
    const cookie = cookies(response, cookies(initiation));
    const sessionResponse = await fetch(`${ctx.baseURL}/api/auth/get-session`, { headers: { cookie } });
    expect(sessionResponse.status).toBe(200);
    const session = await sessionResponse.json();
    expect(session.user.email).toBe(identity.email);
    expect(session.user.emailVerified).toBe(true);
    expect(session.session.userId).toBe(session.user.id);
    const accountsResponse = await fetch(`${ctx.baseURL}/api/auth/list-accounts`, { headers: { cookie } });
    expect(accountsResponse.status).toBe(200);
    const accounts = await accountsResponse.json();
    expect(accounts).toHaveLength(1);
    expect(accounts[0].providerId).toBe("oidc");
    expect(accounts[0].accountId).toBe(identity.sub);
    const stats = await fetch(`${peer}/__test/oauth-proxy/stats`).then(response => response.json());
    expect(stats).toEqual({ users: 0, sessions: 0 });
    return { session, accounts, stats };
  });

  compatScenario("OAuth proxy rejects invalid signed OIDC identities before creating a session", async ctx => {
    const peer = ctx.baseURL === TS_BASE_URL ? RUST_BASE_URL : TS_BASE_URL;
    await fetch(`${peer}/__test/reset-state`, { method: "POST" });
    const rejected: string[] = [];
    for (const mode of ["wrong-signature", "wrong-issuer", "wrong-audience", "expired"]) {
      await control("configure", { email: ctx.uniqueEmail("proxy-invalid"), sub: ctx.uniqueToken("proxy-invalid-subject"), mode });
      const initiation = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/sign-in/social`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ provider: "oidc", callbackURL: "/oidc-return", errorCallbackURL: "/oidc-error", disableRedirect: true }),
      });
      expect(initiation.status).toBe(200);
      const authorization = await fetch((await initiation.json()).url, { redirect: "manual" });
      expect(authorization.status).toBe(302);
      const callback = new URL(authorization.headers.get("location")!);
      const production = await fetch(`${peer}${callback.pathname}${callback.search}`, { redirect: "manual" });
      expect(production.status).toBe(302);
      expect(production.headers.get("location")).toBe("/oidc-error?error=unable_to_get_user_info");
      expect(production.headers.getSetCookie()).toHaveLength(0);
      rejected.push(production.headers.get("location")!);
    }
    const stats = await fetch(`${peer}/__test/oauth-proxy/stats`).then(response => response.json());
    expect(stats).toEqual({ users: 0, sessions: 0 });
    const session = await ctx.actor().client.getSession();
    expect(session.data).toBeNull();
    return { rejected, stats, session };
  });

  compatScenario("OAuth proxy accepts API-key authentication for account linking", async ctx => {
    const signup = await ctx.actor().client.signUp.email({ email: "google@example.com", password: "Password123!", name: "Owner" });
    expect(signup.error).toBeNull();
    const created = await ctx.rawRequest({ path: "/api/auth/api-key/create", method: "POST", json: { configId: "session" } });
    expect(created.status).toBe(200);
    const key = (created.body as { key: string }).key;
    const initiation = await fetch(`${ctx.baseURL}/api/auth/link-social`, {
      method: "POST", headers: { "content-type": "application/json", "x-api-key": key },
      body: JSON.stringify({ provider: "google", callbackURL: "/api-key-return", disableRedirect: true }),
    });
    expect(initiation.status).toBe(200);
    const authorization = new URL((await initiation.json()).url);
    const peer = ctx.baseURL === TS_BASE_URL ? RUST_BASE_URL : TS_BASE_URL;
    const production = await fetch(`${peer}/api/auth/callback/google?${new URLSearchParams({ state: authorization.searchParams.get("state")!, code: "compat-code" })}`, { redirect: "manual" });
    expect(production.status).toBe(302);
    const completion = await fetch(production.headers.get("location")!, { headers: { cookie: cookies(initiation) }, redirect: "manual" });
    expect(completion.status).toBe(302);
    expect(completion.headers.get("location")).toBe("/api-key-return");
    const accounts = await ctx.actor().client.listAccounts();
    expect(accounts.error).toBeNull();
    expect(accounts.data?.map(account => account.providerId).sort()).toEqual(["credential", "google"]);
    const session = await ctx.actor().client.getSession();
    expect(session.data?.user.id).toBe(signup.data?.user.id);
    return { accounts, session };
  });

  if (cookieState) compatScenario("cookie OAuth binds the returned state even when proxying is skipped", async ctx => {
    const response = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/sign-in/social`, {
      method: "POST", headers: { "content-type": "application/json", "x-skip-oauth-proxy": "true" },
      body: JSON.stringify({ provider: "google", callbackURL: "/return", errorCallbackURL: "/failure", disableRedirect: true }),
    });
    expect(response.status).toBe(200);
    const authorization = new URL((await response.json()).url);
    expect(authorization.searchParams.get("redirect_uri")).toBe(`${ctx.baseURL}/api/auth/callback/google`);
    const cookie = cookies(response);
    const wrong = await fetch(`${ctx.baseURL}/api/auth/callback/google?code=compat-code&state=wrong-state`, { headers: { cookie }, redirect: "manual" });
    expect(wrong.status).toBe(302);
    expect(wrong.headers.get("location")).toBe("/failure?error=state_mismatch");
    const retry = await fetch(`${ctx.baseURL}/api/auth/callback/google?${new URLSearchParams({ code: "compat-code", state: authorization.searchParams.get("state")! })}`, { headers: { cookie }, redirect: "manual" });
    expect(retry.status).toBe(302);
    expect(retry.headers.get("location")).toBe("/return");
    return { wrong: { status: wrong.status, location: wrong.headers.get("location") }, retry: { status: retry.status, location: retry.headers.get("location") } };
  });
  for (const legacy of [false, true]) compatScenario(`OAuth proxy completes across runtimes through ${legacy ? "legacy" : "provider"} callback`, async ctx => {
    const flow = await start(ctx);
    if (legacy) flow.completion.pathname = "/api/auth/oauth-proxy-callback";
    const response = await fetch(flow.completion, { headers: { cookie: flow.cookie }, redirect: "manual" });
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/welcome");
    const authenticatedCookie = cookies(response, flow.cookie);
    const sessionResponse = await fetch(`${ctx.baseURL}/api/auth/get-session`, { headers: { cookie: authenticatedCookie } });
    expect(sessionResponse.status).toBe(200);
    const session = await sessionResponse.json();
    expect(session.user.email).toBe("google@example.com");
    expect(session.user.emailVerified).toBe(true);
    expect(session.session.userId).toBe(session.user.id);
    const replay = await fetch(flow.completion, { headers: { cookie: authenticatedCookie }, redirect: "manual" });
    expect(replay.status).toBe(302);
    expect(new URL(replay.headers.get("location")!).origin).toBe(ctx.baseURL);
    expect(new URL(replay.headers.get("location")!).searchParams.get("error")).toBe("state_mismatch");
    return { session, production: flow.productionUnchanged, replay: { location: replay.headers.get("location") } };
  });

  compatScenario("OAuth proxy rejects corrupt, expired, future, provider-mismatched and unbound profiles", async ctx => {
    const flow = await start(ctx);
    const errors: string[] = [];
    const attempt = async (profile: string | null, expected: string, provider = "google") => {
      const target = new URL(flow.completion);
      target.pathname = `/api/auth/callback/${provider}/oauth-proxy`;
      if (profile === null) target.searchParams.delete("profile"); else target.searchParams.set("profile", profile);
      const response = await fetch(target, { headers: { cookie: flow.cookie }, redirect: "manual" });
      expect(response.status).toBe(302);
      const error = new URL(response.headers.get("location")!).searchParams.get("error");
      expect(error).toBe(expected); errors.push(error!);
    };
    await attempt(null, "missing_profile");
    const ciphertext = flow.completion.searchParams.get("profile")!;
    await attempt(`${ciphertext.slice(0, -2)}${ciphertext.endsWith("00") ? "01" : "00"}`, "invalid_profile");
    await attempt(await encode({}), "invalid_payload");
    await attempt(ciphertext, "provider_mismatch", "github");
    await attempt(await encode({ ...flow.profile, timestamp: Date.now() - 61_000 }), "payload_expired");
    await attempt(await encode({ ...flow.profile, timestamp: Date.now() + 11_000 }), "payload_expired");
    await attempt(await encode({ ...flow.profile, state: "different-state" }), "state_mismatch");
    const unauthenticated = await ctx.actor().client.getSession();
    expect(unauthenticated.data).toBeNull();
    const unsafe = new URL(flow.completion);
    unsafe.searchParams.set("callbackURL", "https://attacker.example.com");
    const forbidden = await fetch(unsafe, { headers: { cookie: flow.cookie }, redirect: "manual" });
    expect(forbidden.status).toBe(403);
    return { errors, forbidden: { status: forbidden.status, body: await forbidden.json() } };
  });

  compatScenario("OAuth proxy links an account without creating another preview session", async ctx => {
    const signup = await ctx.actor().client.signUp.email({ email: "google@example.com", password: "Password123!", name: "Owner" });
    expect(signup.error).toBeNull();
    const flow = await start(ctx, true);
    const response = await fetch(flow.completion, { headers: { cookie: flow.cookie }, redirect: "manual" });
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/return");
    expect(response.headers.getSetCookie().some(cookie => cookie.includes("session_token="))).toBe(false);
    const accounts = await ctx.actor().client.listAccounts();
    expect(accounts.error).toBeNull();
    expect(accounts.data?.map(account => account.providerId).sort()).toEqual(["credential", "google"]);
    const session = await ctx.actor().client.getSession();
    expect(session.data?.user.id).toBe(signup.data?.user.id);
    return { accounts, session, production: flow.productionUnchanged };
  });
}
