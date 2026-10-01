import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { anonymous, magicLink } from "better-auth/plugins";
import { APIError, isAPIError, createAuthMiddleware } from "better-auth/api";

const password = "fixture-password";
function context(ctx: any) {
  return { path: ctx.path ?? null, request: !!ctx.request, headers: !!ctx.headers,
    tag: ctx.headers?.get("x-probe-tag") ?? null, bodyKeys: Object.keys(ctx.body ?? {}).sort(),
    hasReturned: ctx.context.returned !== undefined, returnedKeys: Object.keys(ctx.context.returned ?? {}).sort(),
    returnedHidden: ctx.context.returned?.user?.secretNote ?? null,
    hasSetCookie: !!ctx.context.responseHeaders?.get("set-cookie"), location: ctx.context.responseHeaders?.get("location") ?? null,
    actorAnonymous: ctx.context.session?.user?.isAnonymous ?? null };
}
async function observe(response: Response, thrown = false) {
  const text = await response.text(); const body = text ? JSON.parse(text) : null;
  return { status: response.status, thrown, error: response.status >= 400 ? body : null,
    bodyKeys: Object.keys(body ?? {}).sort(), name: body?.user?.name ?? null,
    publicHidden: !!body?.user && Object.hasOwn(body.user, "secretNote"), header: response.headers.get("x-callback-observed"),
    cookies: response.headers.getSetCookie().map(value => ({ name: value.split("=")[0], persistent: value.toLowerCase().includes("max-age=") })) };
}

export function createIdentityContextFixture(baseURL: string) {
  return { async handle(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
    if (path === "/__test/reset-state") return Response.json({ success: true });
    if (path !== "/__test/identity-context") return new Response(null, { status: 404 });
    const input = await request.json(); const events: unknown[] = []; const database = new Database(":memory:");
    const fail = () => {
      if (input.mode === "api-error") throw new APIError("BAD_REQUEST", { code: "CALLBACK_REJECTED", message: "Callback rejected" });
      if (input.mode === "ordinary-error") throw new Error("Callback ordinary failure");
    };
    const options = {
      database, baseURL, secret: "identity-context-secret-at-least-thirty-two-characters", logger: { disabled: true }, rateLimit: { enabled: false },
      emailAndPassword: { enabled: true, autoSignIn: input.autoSignIn !== false, password: { hash: async (value: string) => `fixture:${value}`, verify: async ({ hash, password }: any) => hash === `fixture:${password}` } },
      user: { additionalFields: { secretNote: { type: "string", defaultValue: "issued-secret", returned: false } } },
      session: { expiresIn: 3600, cookieCache: { enabled: false }, additionalFields: { secretSession: { type: "string", defaultValue: "hidden-session", returned: false } } },
      hooks: { after: createAuthMiddleware(async ctx => {
        if (!input.mutate || ctx.path !== "/sign-in/email") return;
        const data = ctx.context.newSession;
        await ctx.context.internalAdapter.updateUser(data.user.id, { name: "Changed after issue", secretNote: "changed-secret" });
        events.push({ event: "application", name: data.user.name, secret: data.user.secretNote });
      }) },
      plugins: [anonymous({
        async generateName(ctx: any) { events.push({ event: "name", context: context(ctx) }); if (input.kind === "name") fail(); return "Anonymous fixture"; },
        async onLinkAccount({ anonymousUser: old, newUser: next, ctx }: any) {
          const stored = await ctx.context.internalAdapter.findUserById(next.user.id);
          events.push({ event: "link", context: context(ctx), oldHidden: old.user.secretNote ?? null, oldSessionHidden: old.session.secretSession ?? null,
            newHidden: next.user.secretNote ?? null, newSessionHidden: next.session.secretSession ?? null, newName: next.user.name,
            storedName: stored.name, storedHidden: stored.secretNote, sameSnapshot: next === ctx.context.newSession,
            oldExists: !!await ctx.context.internalAdapter.findUserById(old.user.id) });
          ctx.setHeader("x-callback-observed", "anonymous-link"); fail();
        },
      }), magicLink({ generateToken: async () => "magic-fixture-token", async sendMagicLink(message: any, ctx: any) {
        events.push({ event: "magic", context: context(ctx), email: message.email, metadata: message.metadata ?? null,
          stored: !!await ctx.context.internalAdapter.findVerificationValue("magic-fixture-token") });
        ctx.setHeader("x-callback-observed", "magic-send"); fail();
      } })],
    };
    const auth = betterAuth(options as any);
    await (await getMigrations(options as any)).runMigrations();
    const names: Record<string, string> = { "/sign-up/email": "signUpEmail", "/sign-in/email": "signInEmail", "/sign-in/anonymous": "signInAnonymous", "/sign-in/magic-link": "signInMagicLink" };
    async function invoke(path: string, body: unknown, cookie = "", control: any = {}) {
      const headers = new Headers({ origin: baseURL, "content-type": "application/json", "x-probe-tag": "callback-fixture" });
      if (cookie) headers.set("cookie", cookie);
      if (control.transport === "native") {
        const value = await (auth.api as any)[names[path]]({ body, ...(control.headers === "omit" ? {} : { headers: control.headers === "empty" ? new Headers() : headers }), returnHeaders: true, returnStatus: true });
        return new Response(JSON.stringify(value.response), { status: value.status ?? 200, headers: value.headers });
      }
      return auth.handler(new Request(`${baseURL}/api/auth${path}`, { method: "POST", headers, body: JSON.stringify(body) }));
    }
    let target = "/sign-in/magic-link", body: any = { email: "magic@example.com", metadata: { label: "metadata" }, unknown: "stripped" }, cookie = "", oldId: string | undefined;
    if (input.kind === "link") {
      await invoke("/sign-up/email", { name: "Original member", email: "member@example.com", password });
      const anonymous = await invoke("/sign-in/anonymous", { marker: "name-body" }); oldId = (await anonymous.json()).user.id;
      cookie = anonymous.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
      target = "/sign-in/email"; body = { email: "member@example.com", password, callbackURL: "/completed", unknown: "stripped" };
    } else if (input.kind === "name") { target = "/sign-in/anonymous"; body = { marker: "name-body" }; }
    else if (input.kind === "signup") {
      target = "/sign-up/email"; body = { name: "Original member", email: "member@example.com", password };
      if (Object.hasOwn(input, "rememberMe")) body.rememberMe = input.rememberMe;
    }
    let output: unknown;
    try { output = await observe(await invoke(target, body, cookie, input)); }
    catch (error: any) {
      if (isAPIError(error)) {
        const headers = Object.getOwnPropertySymbols(error).map(key => error[key]).find(value => value instanceof Headers) ?? error.headers;
        output = await observe(new Response(error.body ? JSON.stringify(error.body) : null, { status: error.statusCode, headers }), true);
      } else output = { thrown: true, message: error.message };
    }
    const member = database.query("select id from user where email=?").get("member@example.com") as { id: string } | null;
    const sessions = member ? database.query("select createdAt,expiresAt from session where userId=?").all(member.id) as { createdAt: number, expiresAt: number }[] : [];
    const result = { output, events, memberExists: !!member, sessions: sessions.length, lifetime: sessions.length ? Math.round((new Date(sessions[0].expiresAt).getTime() - new Date(sessions[0].createdAt).getTime()) / 1000) : null,
      oldExists: oldId ? !!database.query("select id from user where id=?").get(oldId) : null, proof: !!database.query("select id from verification where identifier=?").get("magic-fixture-token") };
    database.close(); return Response.json(result);
  } };
}
