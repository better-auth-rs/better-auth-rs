import { expect } from "bun:test";
import { symmetricDecrypt } from "better-auth/crypto";
import { compatScenario } from "../../../support/scenario";
import { TS_BASE_URL, RUST_BASE_URL } from "../../../support/config";

const scenario = JSON.parse(process.env.COMPAT_PROXY_CASE!);
const secret = "compat-test-only-key-not-real-minimum-32chars";
const decode = async (data: string) => JSON.parse(await symmetricDecrypt({ key: secret, data }));

compatScenario(`OAuth hosting environment: ${scenario.name}`, async ctx => {
  const expand = (value: string) => value.replaceAll("{base}", ctx.baseURL).replaceAll("{host}", new URL(ctx.baseURL).host);
  const response = await fetch(`${ctx.baseURL}/api/auth/sign-in/social`, {
    method: "POST",
    headers: { "content-type": "application/json", host: expand(scenario.host), "x-skip-oauth-proxy": scenario.header },
    body: JSON.stringify({ provider: "google", callbackURL: "/return", disableRedirect: true }),
  });
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(body.redirect).toBe(false);
  const authorization = new URL(body.url);
  expect(authorization.searchParams.get("redirect_uri")).toBe(expand(scenario.redirect));
  expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
  expect(authorization.searchParams.get("code_challenge")).toEqual(expect.any(String));
  const state = authorization.searchParams.get("state")!;
  if (scenario.skip) {
    expect(state.length).toBeLessThan(100);
    return { body, skipped: true };
  }
  const wrapped = await decode(state);
  expect(wrapped.isOAuthProxy).toBe(true);
  const payload = await decode(wrapped.stateCookie);
  expect(payload.oauthState).toBe(wrapped.state);
  expect(payload.codeVerifier.length).toBeGreaterThan(32);
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload.codeVerifier))).toString("base64url");
  expect(authorization.searchParams.get("code_challenge")).toBe(challenge);
  const receiver = new URL(payload.callbackURL);
  expect(receiver.origin).toBe(expand(scenario.receiver));
  expect(receiver.pathname).toBe("/api/auth/callback/google/oauth-proxy");
  expect(receiver.searchParams.get("callbackURL")).toBe("/return");

  const peer = ctx.baseURL === TS_BASE_URL ? RUST_BASE_URL : TS_BASE_URL;
  await fetch(`${peer}/__test/reset-state`, { method: "POST" });
  const production = await fetch(`${peer}/api/auth/callback/google?${new URLSearchParams({ state, code: "compat-code" })}`, { redirect: "manual" });
  expect(production.status).toBe(302);
  expect(production.headers.getSetCookie()).toHaveLength(0);
  expect(await fetch(`${peer}/__test/oauth-proxy/stats`).then(r => r.json())).toEqual({ users: 0, sessions: 0 });
  const completion = new URL(production.headers.get("location")!);
  expect(completion.origin).toBe(receiver.origin);
  const profile = await decode(completion.searchParams.get("profile")!);
  expect(profile.state).toBe(wrapped.state);
  expect(profile.account.providerId).toBe("google");
  expect(profile.account.accountId).toBe("google-account-id");
  // Route the simulated deployment origin to its local fixture without changing the callback payload.
  const cookie = response.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  const result = await fetch(`${ctx.baseURL}${completion.pathname}${completion.search}`, { headers: { cookie }, redirect: "manual" });
  expect(result.status).toBe(302);
  expect(result.headers.get("location")).toBe("/return");
  const sessionCookie = result.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
  const session = await fetch(`${ctx.baseURL}/api/auth/get-session`, { headers: { cookie: sessionCookie } }).then(r => r.json());
  expect(session.user.email).toBe("google@example.com");
  expect(session.session.userId).toBe(session.user.id);
  return { body, callbackURL: receiver.toString(), session };
});
