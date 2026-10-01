import {expect, test} from "bun:test";
import {Database} from "bun:sqlite";
import {betterAuth} from "better-auth";
import {memoryAdapter} from "better-auth/adapters/memory";
import {getMigrations} from "better-auth/db/migration";
import {twoFactor} from "better-auth/plugins";
import {createAuthEndpoint, createAuthMiddleware} from "better-auth/api";
const {expireCookie} = await import(new URL("./cookies/index.mjs", import.meta.resolve("better-auth")).href);

function cacheUsers(headers: Headers) {
  return headers.getSetCookie().filter(line => line.startsWith("better-auth.session_data=") && !line.includes("Max-Age=0")).map(line => {
    const value = decodeURIComponent(line.split(";", 1)[0].slice("better-auth.session_data=".length));
    return JSON.parse(Buffer.from(value, "base64url").toString()).session.user;
  });
}
for (const backend of ["memory", "sqlite"]) for (const mode of ["http", "native"]) {
  test(`${backend} ${mode}: repeated session caches preserve snapshots and 2FA expiration removes credentials`, async () => {
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const options = {
      database: database ?? memoryAdapter({user: [], session: [], account: [], verification: [], twoFactor: []}),
      baseURL: "http://cookies.test", secret: "cookie-response-secret-at-least-32-characters", logger: {disabled: true},
      emailAndPassword: {enabled: true}, session: {cookieCache: {enabled: true}},
      user: {changeEmail: {enabled: true, updateEmailWithoutVerification: true}},
      databaseHooks: {user: {update: {before: async (_: unknown, ctx: any) => ctx?.path === "/change-email" ? false : undefined}}},
      hooks: {after: createAuthMiddleware(async ctx => {
        if (ctx.path !== "/sign-in/email") return;
        await ctx.setSignedCookie("better-auth.dont_remember", "true", "cookie-response-secret-at-least-32-characters");
        ctx.setCookie("better-auth.session_data.0", "pre-challenge");
      })},
      plugins: [twoFactor({skipVerificationOnEnable: true})],
    };
    if (database) await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const signup = await auth.api.signUpEmail({body: {name: "Owner", email: "owner@cookies.test", password: "fixture-password"}, returnHeaders: true});
    const cookie = signup.headers.getSetCookie().map(line => line.split(";", 1)[0]).join("; ");
    const call = async (path: string, method: string, body: object, withCookie: boolean | "token" = true) => {
      const headers = new Headers({"content-type": "application/json", origin: "http://cookies.test", ...(withCookie ? {cookie: withCookie === "token" ? cookie.split("; ").filter(pair => pair.startsWith("better-auth.session_token=")).join("; ") : cookie} : {})});
      if (mode === "http") return auth.handler(new Request(`http://cookies.test/api/auth${path}`, {method: "POST", headers, body: JSON.stringify(body)}));
      return (auth.api as any)[method]({headers, body, asResponse: true});
    };
    const changed = await call("/change-email", "changeEmail", {newEmail: "changed@cookies.test"});
    expect(changed.status).toBe(200);
    expect(cacheUsers(changed.headers).map(user => user.email)).toEqual(["owner@cookies.test", "changed@cookies.test"]);
    const context = await auth.$context;
    expect((await context.internalAdapter.findUserById(signup.response.user.id))?.email).toBe("owner@cookies.test");
    const enabled = await call("/two-factor/enable", "enableTwoFactor", {password: "fixture-password"}, "token");
    expect(enabled.status).toBe(200);
    expect(cacheUsers(enabled.headers).map(user => user.twoFactorEnabled)).toEqual([false, true]);
    const challenge = await call("/sign-in/email", "signInEmail", {email: "owner@cookies.test", password: "fixture-password"}, false);
    expect(challenge.status).toBe(200);
    expect((await challenge.json()).twoFactorRedirect).toBe(true);
    const credentials = challenge.headers.getSetCookie().filter(line => /^better-auth\.session_(token|data)(\.|=)/.test(line));
    expect(credentials).toHaveLength(2);
    expect(credentials.every(line => line.includes("Max-Age=0"))).toBe(true);
    const markers = challenge.headers.getSetCookie().filter(line => line.startsWith("better-auth.dont_remember="));
    expect(markers).toHaveLength(1);
    expect(markers[0].includes("Max-Age=0")).toBe(false);
    database?.close();
  });
}

test("explicit expiration clears both scopes; ordinary repeated writes remain ordered", async () => {
  const auth = betterAuth({baseURL: "http://cookies.test", secret: "cookie-response-secret-at-least-32-characters", logger: {disabled: true}, plugins: [{
    id: "cookie-contract", endpoints: {cookies: createAuthEndpoint("/cookie-contract", {method: "GET"}, async ctx => {
      ctx.setCookie("ordinary", "first");
      ctx.setCookie("ordinary", "second");
      ctx.setCookie("ordinary", "", {maxAge: 0});
      ctx.setCookie("credential", "secret");
      ctx.setCookie("credential.0", "chunk");
      ctx.setCookie("credential-other", "retained");
      ctx.context.responseHeaders = new Headers({"set-cookie": "credential.1=outer-secret; Path=/"});
      expireCookie(ctx, {name: "credential", attributes: {path: "/"}});
      expect(ctx.context.responseHeaders.getSetCookie()).toEqual([]);
      return ctx.json({ok: true});
    })},
  }]});
  const response = await auth.api.cookies({asResponse: true});
  expect(response.headers.getSetCookie().map(line => line.split(";", 1)[0])).toEqual([
    "ordinary=first", "ordinary=second", "ordinary=", "credential-other=retained", "credential=",
  ]);
});
