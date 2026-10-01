import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { createAuthMiddleware } from "better-auth/api";
import { jwt } from "better-auth/plugins";

export async function runJwtSessionScenario(baseURL: string, input: any) {
  const database = new Database(":memory:");
  const events: unknown[] = [];
  const replacement = {id: "replace-session-response", hooks: {after: [{
    matcher: (ctx: any) => ctx.path === "/get-session" && input.state === "replaced",
    handler: createAuthMiddleware(async (ctx: any) => ctx.json({replaced: true})),
  }]}};
  const options: any = {
    database, baseURL, secret: "jwt-session-fixture-secret-at-least-thirty-two-characters",
    logger: {disabled: true}, rateLimit: {enabled: false},
    emailAndPassword: {enabled: true, password: {hash: async () => "fixture-hash", verify: async () => true}},
    plugins: [replacement, jwt({jwt: {definePayload(data: any) {
      const snapshot = {name: data.user.name, expired: new Date(data.session.expiresAt).getTime() < Date.now()};
      events.push({event: "payload", ...snapshot});
      return snapshot;
    }}, adapter: {async getJwks(ctx: any) {
      events.push({event: "get", path: ctx.path, session: !!ctx.context.session, newSession: !!ctx.context.newSession});
      return ctx.context.adapter.findMany({model: "jwks"});
    }}})],
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  try {
    const signup = await auth.api.signUpEmail({body: {name: "Original user", email: "snapshot@example.com", password: "fixture-password"}, returnHeaders: true});
    const adapter = (await auth.$context).adapter;
    if (input.state === "expired") await adapter.update({model: "session", where: [{field: "token", value: signup.response.token}], update: {expiresAt: new Date(Date.now() - 60_000)}});
    if (input.state === "revoked") await adapter.delete({model: "session", where: [{field: "token", value: signup.response.token}]});
    const headers = new Headers({cookie: signup.headers.getSetCookie().map((cookie: string) => cookie.split(";")[0]).join("; ")});
    events.length = 0;
    const result = input.transport === "http"
      ? await auth.handler(new Request(`${baseURL}/api/auth/get-session`, {headers}))
      : await auth.api.getSession({headers, asResponse: true});
    const body: any = await result.json();
    const token = result.headers.get("set-auth-jwt");
    const claims = token ? JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()) : null;
    return {
      status: result.status, body: body === null ? "null" : body.replaced ? "replaced" : "session",
      jwt: claims ? {name: claims.name, expired: claims.expired} : null, events,
      storedSessions: (database.query("select count(*) as count from session").get() as {count: number}).count,
    };
  } finally { database.close(); }
}
