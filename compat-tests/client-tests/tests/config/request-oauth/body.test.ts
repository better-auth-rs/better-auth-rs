import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import contracts from "./invalid-inputs.json";

async function post(ctx: any, path: string, body: any, headers: Record<string, string> = {}) {
  return fetch(`${ctx.baseURL}${path}`, {
    method: "POST", headers: { "content-type": "application/json", origin: ctx.baseURL, ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}
function call(ctx: any, mode: string, path: string, body: any, headers: Record<string, string> = {}) {
  return mode === "http" ? post(ctx, `/api/auth${path}`, body, headers)
    : post(ctx, "/__test/query-native", { path, method: "POST", ...(body === undefined ? {} : { body }), headers });
}
async function events(ctx: any) { return (await (await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events; }
async function clear(ctx: any) { await post(ctx, "/__test/body-events", {}); await post(ctx, "/__test/email-events", {}); }
async function account(ctx: any, accountId: string) { return (await post(ctx, "/__test/oauth-account", { accountId })).json(); }
async function projection(ctx: any, mode: string, raw: any, projected: any, phases: string[]) {
  const trace = await events(ctx);
  for (const phase of phases) expect(trace.some((event: any) => event.phase === phase)).toBe(true);
  for (const event of trace) {
    expect(event.body).toEqual(["before", "plugin.before", "after"].includes(event.phase) ? raw : projected);
    expect(event.request).toBe(mode === "http");
    expect(event.requestBody).toBe(mode === "http" ? JSON.stringify(raw) : null);
  }
  return trace;
}

for (const mode of ["http", "native"]) {
  compatScenario(`${mode}: OAuth schemas preserve nested error order before session authentication`, async ctx => {
    const results = [];
    for (const entry of contracts) {
      await clear(ctx);
      const body = entry.omitted ? undefined : entry.body;
      const response = await call(ctx, mode, entry.path, body);
      const result = await response.json();
      const originReject = mode === "http" && typeof body?.callbackURL === "number";
      expect(response.status).toBe(400);
      expect(result).toEqual(originReject ? { message: "Invalid callbackURL: expected a string" } : entry.result);
      const trace = await events(ctx);
      expect(trace.map((event: any) => event.phase)).toEqual(originReject ? [] : ["before", "plugin.before", "after"]);
      for (const event of trace) {
        expect(event.body).toEqual(body === undefined ? { $undefined: true } : body);
        expect(event.request).toBe(mode === "http");
      }
      results.push({ path: entry.path, result, trace });
    }
    if (mode === "native") {
      const missing = await post(ctx, "/__test/query-native", { path: "/link-social", method: "POST", body: { provider: "google" } });
      expect(missing.status).toBe(400);
      expect(await missing.json()).toEqual({ code: "VALIDATION_ERROR", message: "Headers is required" });
    }
    return results;
  });

  compatScenario(`${mode}: OAuth strips nested fields and preserves distinct signin and linking token writes`, async ctx => {
    const email = ctx.uniqueEmail(`oauth-body-${mode}`);
    const raw = {
      provider: "google", unknown: "raw", scopes: ["requested"], idToken: {
        token: "signin-token", nonce: "nonce", accessToken: email, refreshToken: "signin-refresh",
        expiresAt: 12.75, scopes: ["ignored"], unknown: "nested",
        user: { name: { firstName: "Given", lastName: "Family", unknown: true }, email, unknown: 7 },
      },
    };
    const projected = {
      provider: "google", scopes: ["requested"], idToken: {
        token: "signin-token", nonce: "nonce", accessToken: email, refreshToken: "signin-refresh", expiresAt: 12.75,
        user: { name: { firstName: "Given", lastName: "Family" }, email },
      },
    };
    await clear(ctx);
    const signed = await call(ctx, mode, "/sign-in/social", raw);
    expect(signed.status).toBe(200);
    expect((await signed.json()).user.email).toBe(email);
    const signinTrace = await projection(ctx, mode, raw, projected, ["oauth.verify", "oauth.userinfo", "user.before", "session.before"]);
    const sender = (await (await fetch(`${ctx.baseURL}/__test/email-events`)).json()).events;
    expect(sender).toEqual([{
      kind: "oauth-userinfo", accessToken: email, refreshToken: "signin-refresh", expiresAt: null, scopes: [], idToken: "signin-token",
      userPresent: true, firstName: "Given", lastName: "Family", email,
    }]);
    expect(await account(ctx, email)).toEqual({ accessToken: email, refreshToken: null, idToken: "signin-token", scope: null, expiresAt: null });
    const headers = { cookie: signed.headers.getSetCookie().map(line => line.split(";", 1)[0]).join("; ") };
    const link = {
      provider: "google", unknown: true, newUserCallbackURL: "/ignored",
      idToken: { token: "link-token", accessToken: email, refreshToken: "link-refresh", scopes: false, expiresAt: null, user: false, unknown: true },
    };
    const projectedLink = { provider: "google", idToken: { token: "link-token", accessToken: email, refreshToken: "link-refresh" } };
    await clear(ctx);
    const linked = await call(ctx, mode, "/link-social", link, headers);
    expect(linked.status).toBe(200);
    expect((await linked.json()).status).toBe(true);
    const linkTrace = await projection(ctx, mode, link, projectedLink, ["oauth.verify", "oauth.userinfo"]);
    const linkSender = (await (await fetch(`${ctx.baseURL}/__test/email-events`)).json()).events;
    expect(linkSender).toEqual([{
      kind: "oauth-userinfo", accessToken: email, refreshToken: "link-refresh", expiresAt: null, scopes: [], idToken: "link-token",
      userPresent: false, firstName: null, lastName: null, email: null,
    }]);
    const stored = await account(ctx, email);
    expect(stored).toEqual({ accessToken: email, refreshToken: "link-refresh", idToken: "link-token", scope: null, expiresAt: null });
    const rejected = await call(ctx, mode, "/link-social", { ...link, idToken: { ...link.idToken, token: "rejected-token" } }, headers);
    expect(rejected.status).toBe(401);
    expect(await rejected.json()).toEqual({ code: "INVALID_TOKEN", message: "Invalid token" });
    expect(await account(ctx, email)).toEqual(stored);
    return { signinTrace, linkTrace, sender, linkSender, stored };
  });
}
