import { betterAuth } from "better-auth";
import { APIError, createAuthEndpoint, createAuthMiddleware } from "better-auth/api";

export function createApiErrorFixture(baseURL: string) {
  return {
    async handle(request: Request): Promise<Response> {
      const path = new URL(request.url).pathname;
      if (["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
      if (path === "/__test/reset-state") return Response.json({ success: true });
      if (path !== "/__test/api-error") return new Response(null, { status: 404 });
      const input = await request.json();
      const events: string[] = [];
      const released = Promise.withResolvers<void>();
      const finished = Promise.withResolvers<void>();
      function failure() {
        if (input.kind === "found") throw new APIError("FOUND", undefined, { location: "/target" });
        if (input.kind === "numeric302") throw new APIError(302, undefined, { location: "/target" });
        if (input.kind === "redirect307") throw new APIError("TEMPORARY_REDIRECT", undefined, { location: "/target" });
        if (input.kind === "api") throw new APIError("BAD_REQUEST", { code: "FIXTURE", message: "invalid" });
        throw new Error("original failure");
      }
      const onError = input.callback === "async" ? async () => {
        events.push("callback-start"); await released.promise;
        events.push("callback-finish"); finished.resolve();
      } : input.callback ? () => {
        events.push("callback");
        if (input.callback === "throw") throw new Error("callback failure");
        if (input.callback === "throw-api") throw new APIError("BAD_GATEWAY", { message: "callback failure" });
        return new Response("ignored", { status: 418 });
      } : undefined;
      const auth = betterAuth({
        baseURL, secret: "api-error-fixture-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, rateLimit: { enabled: false }, emailAndPassword: { enabled: true },
        onAPIError: { throw: input.throw ?? false, onError, errorURL: input.errorURL, customizeDefaultErrorPage: input.customize },
        plugins: [{ id: "api-error-fixture",
          onRequest: async () => { if (input.phase === "onRequest") { events.push("onRequest"); failure(); } },
          onResponse: async () => { if (input.phase === "onResponse") { events.push("onResponse"); failure(); } },
          hooks: {
            before: [{ matcher: c => c.path === "/fixture-error", handler: createAuthMiddleware(async () => {
              events.push("before"); if (input.phase === "before") failure();
            }) }],
            after: [{ matcher: c => c.path === "/fixture-error", handler: createAuthMiddleware(async () => {
              events.push("after"); if (input.phase === "after") failure();
            }) }],
          },
          endpoints: { fixtureError: createAuthEndpoint("/fixture-error", { method: "GET" }, async c => {
            events.push("handler"); if (input.phase === "handler") failure(); return c.json({ ok: true });
          }) },
        }],
      });
      await auth.$context;
      const endpoint = input.oauth ? "/callback/mock" : input.page ? "/error" : input.bodyCase ? "/sign-in/email" : "/fixture-error";
      const req = new Request(`${baseURL}/api/auth${endpoint}${input.query ?? ""}`, input.bodyCase ? {
        method: "POST", headers: { origin: baseURL, "content-type": input.bodyCase === "media" ? "text/plain" : "application/json" },
        body: input.bodyCase === "malformed" ? "{" : input.bodyCase === "media" ? "bad" : JSON.stringify({ email: "invalid", password: "password" }),
      } : undefined);
      function ordinaryMessage(error: any) {
        return ["original failure", "callback failure"].includes(error.message) ? error.message : "runtime error";
      }
      async function observe(response: Response, thrown = false) {
        const body = await response.text();
        return {
          thrown, status: response.status, location: response.headers.get("location"), contentType: response.headers.get("content-type"),
          ...(response.headers.get("content-type") === "text/html" ? { matches: (input.needles ?? []).map((needle: string) => body.includes(needle)) } : { body: body && response.headers.get("content-type")?.includes("application/json") ? JSON.parse(body) : body }),
        };
      }
      let output: unknown;
      try {
        if (input.transport === "native") {
          const options = { request: input.nativeRequest ? req : undefined, query: input.nativeQuery, asResponse: false };
          const value = input.page ? await auth.api.error(options) : await auth.api.fixtureError(options);
          output = value instanceof Response ? await observe(value) : { thrown: false, value };
        } else output = await observe(await auth.handler(req));
      } catch (error: any) {
        output = error instanceof APIError
          ? { thrown: true, status: error.statusCode, body: error.body ?? "", location: new Headers(error.headers).get("location") }
          : { thrown: true, message: ordinaryMessage(error) };
      }
      const beforeRelease = [...events];
      if (events.includes("callback-start")) { released.resolve(); await finished.promise; }
      return Response.json({ output, events: beforeRelease, completed: [...events] });
    },
  };
}
