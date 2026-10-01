import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";

export async function createStatelessFixture(profile: string, baseURL: string) {
  const cache = new Map<string, { value: string; expires?: number }>();
  let events: unknown[] = [];
  let tokenRequests: unknown[] = [];
  const secondaryStorage = {
    async get(key: string) {
      const item = cache.get(key);
      return item && (item.expires === undefined || item.expires > Date.now()) ? item.value : null;
    },
    async set(key: string, value: string, ttl?: number) {
      cache.set(key, { value, expires: ttl === undefined ? undefined : Date.now() + ttl * 1000 });
    },
    async delete(key: string) { cache.delete(key); },
    async getAndDelete(key: string) { const value = await this.get(key); cache.delete(key); return value; },
  };
  const record = (kind: string, row: any, context: any) => {
    events.push({ kind, email: row?.email ?? null, path: context?.path ?? null, http: Boolean(context?.request) });
  };
  async function build() {
    const explicit = profile === "stateless-explicit";
    const refreshing = profile === "stateless-refresh" || profile === "stateless-no-refresh";
    const auth = betterAuth({
      baseURL,
      secret: "compat-test-only-key-not-real-minimum-32chars",
      rateLimit: { enabled: false },
      session: {
        expiresIn: 600,
        ...(explicit ? { cookieCache: { enabled: false, refreshCache: false } } : {}),
        ...(refreshing ? { cookieCache: { maxAge: 5, refreshCache: profile === "stateless-refresh" ? { updateAge: 4 } : false } } : {}),
        ...(profile === "stateless-secondary" ? { cookieCache: { enabled: true, strategy: "jwe", maxAge: 60, refreshCache: true } } : {}),
      },
      ...(explicit ? { account: { storeAccountCookie: false, storeStateStrategy: "database" } } : {}),
      ...(profile === "stateless-secondary" ? { secondaryStorage } : {}),
      emailAndPassword: { enabled: true, password: { hash: async value => `fixture:${value}`, verify: async ({ hash, password }) => hash === `fixture:${password}` } },
      plugins: [genericOAuth({ config: [{
        providerId: "mock", clientId: "fixture-client", clientSecret: "fixture-secret", pkce: true,
        authorizationUrl: `${baseURL}/__test/provider/authorize`,
        tokenUrl: `${baseURL}/__test/provider/token`, userInfoUrl: `${baseURL}/__test/provider/user`, scopes: ["email"],
      }] })],
      databaseHooks: {
        user: { create: { before: async (row, ctx) => { record("user.before", row, ctx); return { data: row }; }, after: async (row, ctx) => { record("user.after", row, ctx); } } },
        session: { create: { before: async (row, ctx) => { record("session.before", row, ctx); return { data: row }; }, after: async (row, ctx) => { record("session.after", row, ctx); } } },
      },
    });
    await auth.$context;
    return auth;
  }
  let auth = await build();
  return {
    async handle(request: Request): Promise<Response> {
      const url = new URL(request.url);
      if (["/health", "/__health"].includes(url.pathname)) return Response.json({ status: "ok" });
      if (url.pathname === "/__test/reset-state") {
        cache.clear(); events = []; tokenRequests = []; auth = await build();
        return Response.json({ success: true });
      }
      if (url.pathname === "/__test/stateless") {
        const body = request.method === "POST" ? await request.json() : {};
        if (body.restart) auth = await build();
        const context = await auth.$context;
        if (body.revoke) await context.internalAdapter.deleteSession(body.revoke);
        if (body.clearEvents) events = [];
        return Response.json({ events, tokenRequests, users: (await context.adapter.findMany({ model: "user" })).length });
      }
      if (url.pathname === "/__test/cached-session") {
        const { response, headers } = await auth.api.getSession({ headers: request.headers, returnHeaders: true });
        return Response.json(response, { status: response ? 200 : 401, headers });
      }
      if (url.pathname === "/__test/provider/token") {
        const form = new URLSearchParams(await request.text());
        const grant = form.get("grant_type");
        tokenRequests.push({ grant, verifier: Boolean(form.get("code_verifier")), refresh: form.get("refresh_token") });
        return Response.json({ access_token: grant === "refresh_token" ? "refreshed-access" : "initial-access", refresh_token: "refresh-token", token_type: "Bearer", expires_in: 60, scope: "email" });
      }
      if (url.pathname === "/__test/provider/user") return Response.json({ id: "provider-user", email: "stateless@example.com", email_verified: true, name: "Stateless" });
      return auth.handler(request);
    },
  };
}
