import { betterAuth } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";

export const profiles = ["trailing-slashes-default", "trailing-slashes-true", "trailing-slashes-false"];

function requestURL(request?: Request) {
  if (!request) return null;
  const url = new URL(request.url);
  return `${url.pathname}${url.search}`;
}

export function createTrailingSlashesFixture(profile: string, baseURL: string) {
  if (!profiles.includes(profile)) throw new Error(`Unknown profile: ${profile}`);
  const events: unknown[] = [];
  function record(phase: string, context: any) {
    const event = { phase, path: context.path, url: requestURL(context.request), method: context.method, params: context.params ?? {} };
    events.push(event);
    return event;
  }
  const endpoint = (path: string) => createAuthEndpoint(path, { method: ["GET", "POST"] }, async ctx => {
    const event = record("endpoint", ctx);
    return ctx.json({ ...event, body: ctx.body ?? null, query: ctx.query ?? {} });
  });
  const auth = betterAuth({
    baseURL, secret: "trailing-slashes-fixture-secret-with-at-least-32-characters",
    rateLimit: { enabled: false }, logger: { disabled: true },
    ...(profile === "trailing-slashes-default" ? {} : { advanced: { skipTrailingSlashes: profile === "trailing-slashes-true" } }),
    disabledPaths: ["/disabled", "/disabled-slash-config/", "/disabled-declared", "/dynamic/blocked"],
    plugins: [{
      id: "trailing-slashes-fixture",
      onRequest: async request => {
        events.push({ phase: "http", url: requestURL(request), method: request.method });
        if (new URL(request.url).pathname === "/api/auth/early") return { response: Response.json({ early: true }, { status: 202 }) };
      },
      onResponse: async response => {
        events.push({ phase: "response", status: response.status });
        if ((events[0] as any)?.url === "/api/auth/replace-response") return { response: Response.json({ replaced: true }, { status: 202 }) };
        if ((events[0] as any)?.url === "/api/auth/response-chain") response.headers.set("x-response-chain", "first");
      },
      hooks: {
        before: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => { record("before", ctx); }) }],
        after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => { record("after", ctx); }) }],
      },
      endpoints: {
        probe: endpoint("/probe"), declared: endpoint("/declared/"), dynamic: endpoint("/dynamic/:id"),
        disabled: endpoint("/disabled"), disabledSlashConfig: endpoint("/disabled-slash-config"),
        disabledDeclared: endpoint("/disabled-declared/"), root: endpoint("/"), replace: endpoint("/replace-response"), chain: endpoint("/response-chain"),
      },
    }, {
      id: "trailing-slashes-later-response",
      onResponse: async response => {
        if ((events[0] as any)?.url === "/api/auth/replace-response") events.push({ phase: "later-response" });
        if ((events[0] as any)?.url === "/api/auth/response-chain") {
          events.push({ phase: "later-response", header: response.headers.get("x-response-chain") });
          response.headers.set("x-response-chain", "second");
        }
      },
    }],
  });
  return {
    auth,
    async handle(request: Request): Promise<Response> {
      const path = new URL(request.url).pathname;
      if (["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
      if (path === "/__test/reset-state") { events.length = 0; return Response.json({ success: true }); }
      if (path === "/__test/trailing-slashes") {
        if (request.method === "POST") events.length = 0;
        return Response.json({ events });
      }
      return auth.handler(request);
    },
  };
}
