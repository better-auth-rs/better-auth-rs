import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { lastLoginMethod } from "better-auth/plugins";

export async function createLastLoginFixture(profile: string, baseURL: string) {
  let events: any[] = [];
  let controls: any = {};
  let resolves = 0;
  const cache = new Map<string, string>();
  const persist = profile !== "last-login-cookie";
  const record = (kind: string, context: any, value?: unknown) => {
    events.push({ kind, path: context?.path ?? null, http: Boolean(context?.request), ...(value === undefined ? {} : { value }) });
  };
  const failure = () => APIError.from("FORBIDDEN", { code: "LOGIN_FIXTURE_REJECTED", message: "Login fixture rejected" });
  const database = profile === "last-login-ephemeral" ? undefined : new Database(":memory:");
  const options: any = {
    baseURL,
    secret: "compat-test-only-key-not-real-minimum-32chars",
    database,
    rateLimit: { enabled: false },
    emailAndPassword: { enabled: true, password: { hash: async (value: string) => `fixture:${value}`, verify: async ({ hash, password }: any) => hash === `fixture:${password}` } },
    session: { cookieCache: { enabled: true } },
    hooks: { before: createAuthMiddleware(async ctx => {
      if (typeof controls.replaceName === "string") return { context: { body: { ...ctx.body, name: controls.replaceName } } };
    }) },
    ...(profile === "last-login-secondary" ? { secondaryStorage: {
      async get(key: string) { return cache.get(key) ?? null; },
      async set(key: string, value: string) { cache.set(key, value); },
      async delete(key: string) { cache.delete(key); },
      async getAndDelete(key: string) { const value = cache.get(key) ?? null; cache.delete(key); return value; },
    } } : {}),
    ...(profile === "last-login-fields" ? { user: { additionalFields: { lastLoginMethod: {
      type: "string", required: true, input: true, returned: false, fieldName: "alias",
      transform: { input: (value: string) => `${value}:in`, output: (value: string) => `${value}:out` },
    } } } } : {}),
    plugins: [lastLoginMethod({
      storeInDatabase: persist,
      ...(profile === "last-login-cookie" ? { cookieName: "__Host-login_hint", maxAge: 90.9 } : {}),
      schema: { user: { lastLoginMethod: "storedLabel" } },
      customResolveMethod(ctx) {
        resolves++;
        record("resolve", ctx);
        events[events.length - 1].header = ctx.headers?.get("x-login-context") ?? null;
        if (controls.resolve === "body") {
          events[events.length - 1].bodyName = ctx.body?.name ?? null;
          return ctx.body?.name ?? "missing";
        }
        if (controls.resolve === "error" || controls.resolve === "session-error" && resolves === 2) throw failure();
        if (controls.resolve === "empty") return "";
        if (controls.resolve === "custom") return "custom method";
        return null;
      },
      async beforeStoreCookie(ctx, method) {
        record("cookie", ctx, method);
        if (controls.resolve === "body") events[events.length - 1].bodyName = ctx.body?.name ?? null;
        if (controls.veto === "error") throw failure();
        return controls.veto !== "deny";
      },
    })],
    databaseHooks: {
      user: {
        create: { before: async (row: any, ctx: any) => { record("user.before", ctx, row.lastLoginMethod ?? null); return { data: row }; }, after: async (_: any, ctx: any) => { record("user.after", ctx); } },
        update: { before: async (row: any, ctx: any) => { record("user.update", ctx, row.lastLoginMethod ?? null); if (controls.fail === "update") throw failure(); return { data: row }; }, after: async (_: any, ctx: any) => { record("user.updated", ctx); } },
      },
      session: { create: {
        before: async (row: any, ctx: any) => { record("session.before", ctx); if (controls.fail === "session") throw failure(); return { data: row }; },
        after: async (_: any, ctx: any) => { record("session.after", ctx); },
      } },
    },
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  await auth.$context;
  return {
    async handle(request: Request) {
      const path = new URL(request.url).pathname;
      if (["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
      if (path === "/__test/reset-state") {
        const context = await auth.$context;
        for (const model of [...(profile === "last-login-secondary" ? [] : ["session"]), "account", "user"]) await context.adapter.deleteMany({ model, where: [] });
        events = []; controls = {}; resolves = 0; cache.clear();
        return Response.json({ success: true });
      }
      if (path === "/__test/last-login/native") {
        const result = await auth.api.signUpEmail({ body: await request.json(), headers: new Headers({ "x-login-context": "native-header" }), returnHeaders: true });
        return Response.json({ body: result.response, cookies: result.headers.getSetCookie() });
      }
      if (path === "/__test/last-login") {
        if (request.method === "POST") { controls = await request.json(); events = []; resolves = 0; }
        const context = await auth.$context;
        const users = await context.adapter.findMany({ model: "user" });
        return Response.json({ events, users: users.map((user: any) => ({ email: user.email, method: user.lastLoginMethod ?? null })), cache: [...cache.values()].filter(value => value.includes('"user"')).map(value => { const data = JSON.parse(value); return { method: data.user?.lastLoginMethod ?? null }; }) });
      }
      return auth.handler(request);
    },
  };
}
