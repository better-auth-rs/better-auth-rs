import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

async function post(ctx: any, path: string, body: any, headers: Record<string, string> = {}) {
  return fetch(`${ctx.baseURL}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: ctx.baseURL, ...headers }, body: JSON.stringify(body) });
}
async function call(ctx: any, mode: string, path: string, body: any, headers: Record<string, string> = {}) {
  return mode === "http" ? post(ctx, `/api/auth${path}`, body, headers) : post(ctx, "/__test/query-native", { path, method: "POST", body, headers });
}
async function clear(ctx: any) { await post(ctx, "/__test/body-events", {}); }
async function events(ctx: any) { return (await (await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events; }
async function signup(ctx: any, suffix: string) {
  const response = await post(ctx, "/api/auth/sign-up/email", { name: "Account schema", email: `account-schema-${suffix}@query.example`, password: "fixture-password" });
  expect(response.status).toBe(200);
  return { ...(await response.json()), cookie: response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ") };
}

for (const mode of ["http", "native"]) {
  compatScenario(`${mode}: account, user, and session body schemas fail before authentication`, async ctx => {
    const results = [];
    const cases: [string, any, string][] = [
      ["/revoke-session", {}, "[body.token] Invalid input: expected string, received undefined"],
      ["/revoke-session", { token: [] }, "[body.token] Invalid input: expected string, received array"],
      ["/unlink-account", { accountId: null }, "[body.accountId] Invalid input: expected string, received null"],
      ["/change-email", { newEmail: "invalid", callbackURL: 7 }, "[body.newEmail] Invalid email address; [body.callbackURL] Invalid input: expected string, received number"],
      ["/delete-user", { callbackURL: 7, password: false, token: [] }, "[body.callbackURL] Invalid input: expected string, received number; [body.password] Invalid input: expected string, received boolean; [body.token] Invalid input: expected string, received array"],
      ["/get-access-token", { accountId: "missing", unknown: "strict" }, '[body] Unrecognized key: "unknown"'],
      ["/get-access-token", { accountId: "missing", useAccountCookie: true }, "[body] Invalid input"],
      ["/refresh-token", { useAccountCookie: "true" }, "[body] Invalid input"],
      ["/refresh-token", null, "[body] Invalid input"],
    ];
    for (const [path, body, message] of cases) {
      await clear(ctx);
      const response = await call(ctx, mode, path, body);
      expect(response.status).toBe(400);
      const value = await response.json();
      const rejectedByOrigin = mode === "http" && typeof body?.callbackURL === "number";
      expect(value).toEqual(rejectedByOrigin ? { message: "Invalid callbackURL: expected a string" } : { code: "VALIDATION_ERROR", message });
      const trace = await events(ctx);
      expect(trace.map((event: any) => event.phase)).toEqual(rejectedByOrigin ? [] : ["before", "plugin.before", "after"]);
      for (const event of trace) { expect(event.body).toEqual(body); expect(event.request).toBe(mode === "http"); }
      results.push({ path, value, trace });
    }
    return results;
  });

  compatScenario(`${mode}: validated session revocation and email change strip unknown fields before storage hooks`, async ctx => {
    const owner = await signup(ctx, mode);
    const headers = { cookie: owner.cookie };
    await clear(ctx);
    const empty = await call(ctx, mode, "/revoke-session", { token: "", unknown: "raw" }, headers);
    expect(empty.status).toBe(200); expect(await empty.json()).toEqual({ status: true });
    const emptyTrace = await events(ctx);
    expect(emptyTrace.map((event: any) => event.phase)).toEqual(["before", "plugin.before", "after"]);

    const changedBody = { newEmail: `changed-${mode}@query.example`, callbackURL: "/after-change", unknown: "raw" };
    await clear(ctx);
    const changed = await call(ctx, mode, "/change-email", changedBody, headers);
    expect(changed.status).toBe(200); expect(await changed.json()).toEqual({ status: true });
    const changeTrace = await events(ctx);
    expect(changeTrace.map((event: any) => event.phase)).toEqual(["before", "plugin.before", "user.update.before", "user.update.after", "after"]);
    for (const event of changeTrace) {
      expect(event.body).toEqual(event.phase.startsWith("user.") ? { newEmail: changedBody.newEmail, callbackURL: changedBody.callbackURL } : changedBody);
      expect(event.requestBody).toBe(mode === "http" ? JSON.stringify(changedBody) : null);
    }

    const revokeBody = { token: owner.token, unknown: "raw" };
    await clear(ctx);
    const revoked = await call(ctx, mode, "/revoke-session", revokeBody, headers);
    expect(revoked.status).toBe(200); expect(await revoked.json()).toEqual({ status: true });
    const revokeTrace = await events(ctx);
    expect(revokeTrace.map((event: any) => event.phase)).toEqual(["before", "plugin.before", "session.delete.before", "session.delete.after", "after"]);
    for (const event of revokeTrace) {
      expect(event.body).toEqual(event.phase.startsWith("session.") ? { token: owner.token } : revokeBody);
      expect(event.requestBody).toBe(mode === "http" ? JSON.stringify(revokeBody) : null);
      event.body.token = "<session-token>";
      if (event.requestBody) event.requestBody = event.requestBody.replace(owner.token, "<session-token>");
    }
    const session = await post(ctx, "/__test/query-native", { path: "/get-session", headers, query: { disableCookieCache: true } });
    expect(session.status).toBe(200); expect(await session.json()).toBeNull();
    return { emptyTrace, changeTrace, revokeTrace };
  });
}
