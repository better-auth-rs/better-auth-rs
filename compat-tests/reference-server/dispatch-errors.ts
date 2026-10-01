import { betterAuth } from "better-auth";
import { APIError, createAuthEndpoint, createAuthMiddleware } from "better-auth/api";

function observedHeaders(headers: Headers) {
  return {
    priority: headers.get("x-priority"), later: headers.get("x-later-hook"), location: headers.get("location"),
    cookies: headers.getSetCookie().map(value => value.split("=")[0]),
  };
}

export function createDispatchErrorsFixture(baseURL: string) {
  return {
    async handle(request: Request): Promise<Response> {
      const path = new URL(request.url).pathname;
      if (["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
      if (path === "/__test/reset-state") return Response.json({ success: true });
      if (path !== "/__test/dispatch-errors") return new Response(null, { status: 404 });
      const input = await request.json();
      const events: unknown[] = [];
      function failure() {
        if (input.mode === "ordinary-error") throw new Error("Fixture ordinary failure");
        const headers = { "x-priority": "explicit-error", "set-cookie": "explicit_error_cookie=1; Path=/", location: "/explicit-error" };
        if (input.mode === "redirect") throw new APIError("FOUND", undefined, headers);
        throw new APIError(input.mode === "api-500" ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST", { code: "FIXTURE_REJECTED", message: "Fixture rejected" }, headers);
      }
      function mutate(ctx: any, label: string) {
        ctx.setHeader("x-priority", label);
        ctx.setHeader("set-cookie", `${label}_cookie=1; Path=/`);
      }
      const auth = betterAuth({
        baseURL, secret: "dispatch-fixture-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, rateLimit: { enabled: false }, session: { cookieCache: { enabled: false } },
        plugins: [{
          id: "fixture-first",
          onRequest: async () => { events.push({ hook: "http" }); if (input.phase === "http") failure(); },
          hooks: {
            before: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => {
              events.push({ hook: "before" });
              if (input.phase !== "before") return;
              mutate(ctx, "before");
              if (input.mode === "response") return ctx.json({ early: true });
              failure();
            }) }],
            after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => {
              events.push({ hook: "after-first", apiError: ctx.context.returned instanceof APIError });
              if (input.phase !== "after") return;
              mutate(ctx, "after");
              if (input.mode === "response") return ctx.json({ recovered: true });
              failure();
            }) }],
          },
          endpoints: { fixtureProbe: createAuthEndpoint("/fixture-probe", { method: "GET" }, async ctx => {
            events.push({ hook: "endpoint" });
            await ctx.context.internalAdapter.createVerificationValue({ identifier: "fixture-write", value: "persisted", expiresAt: new Date(Date.now() + 60_000) });
            mutate(ctx, "endpoint");
            if (input.phase === "endpoint" || input.endpointError) {
              if (input.phase === "endpoint" && input.mode === "response") return new Response(JSON.stringify({ response: true }), { status: 400 });
              failure();
            }
            return ctx.json({ accepted: true });
          }) },
        }, { id: "fixture-later", hooks: { after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => {
          events.push({ hook: "after-later", apiError: ctx.context.returned instanceof APIError, ...observedHeaders(ctx.context.responseHeaders) });
          ctx.setHeader("x-later-hook", "ran");
        }) }] } }],
      });
      let output: unknown;
      try {
        if (input.transport === "native") {
          const value = await auth.api.fixtureProbe({ returnHeaders: true, returnStatus: true });
          if (value.response instanceof Response) output = { thrown: false, status: value.response.status, body: await value.response.text(), ...observedHeaders(value.headers) };
          else output = { thrown: false, status: value.status ?? 200, body: JSON.stringify(value.response), ...observedHeaders(value.headers) };
        } else {
          const response = await auth.handler(new Request(`${baseURL}/api/auth/fixture-probe`));
          output = { thrown: false, status: response.status, body: await response.text(), ...observedHeaders(response.headers) };
        }
      } catch (error: any) {
        if (error instanceof APIError) {
          const captured = Object.getOwnPropertySymbols(error).map(key => error[key]).find(value => value instanceof Headers);
          output = { thrown: true, status: error.statusCode, body: error.body ? JSON.stringify(error.body) : "", ...observedHeaders(captured ?? new Headers(error.headers)), errorHeaders: observedHeaders(new Headers(error.headers)), contextHeaders: captured ? observedHeaders(captured) : null };
        } else output = { thrown: true, message: error.message };
      }
      const context = await auth.$context;
      const persisted = Boolean(await context.internalAdapter.findVerificationValue("fixture-write"));
      return Response.json({ output, events, persisted });
    },
  };
}
