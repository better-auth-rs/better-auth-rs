import { runIdPolicy } from "./id-policy";
import { runDynamicOAuth } from "./dynamic-oauth";
import { runDynamicCookies } from "./dynamic-cookies";
import { runDynamicNative } from "./dynamic-native";
import { betterAuth } from "better-auth";
import { APIError, createAuthEndpoint, createAuthMiddleware, isAPIError } from "better-auth/api";

type DynamicURL = { allowedHosts: string[]; fallback?: string; protocol?: "http" | "https" | "auto" };
type Call = {
  id: string;
  transport: "http" | "native";
  method?: "GET" | "POST";
  url?: string;
  requestHeaders?: Record<string, string>;
  headers?: Record<string, string>;
  nativeRequest?: boolean;
  rawBody?: string;
};
export type Input = {
  baseURL?: string | DynamicURL;
  basePath?: string;
  proxy?: boolean;
  crossSubdomain?: boolean;
  defaultCookieDomain?: string;
  sessionCookieDomain?: string;
  origins?: string[];
  providers?: string[];
  pluginOrigins?: { id: string; values: string[]; dynamic: boolean }[];
  parallel?: boolean;
  calls: Call[];
};
type Event = { stage: string; request: ReturnType<typeof requestValue>; baseURL?: string };

function requestValue(request?: Request) {
  return request ? {
    id: request.headers.get("x-probe-id"), url: request.url, method: request.method,
    host: request.headers.get("host"), forwardedHost: request.headers.get("x-forwarded-host"),
    forwardedProto: request.headers.get("x-forwarded-proto"), tenant: request.headers.get("x-tenant"),
  } : null;
}
function errorValue(error: any) {
  return isAPIError(error)
    ? { thrown: true, kind: "APIError", status: error.statusCode, body: error.body ?? null }
    : { thrown: true, kind: error.name, message: error.message };
}
function contextValue(context: any) {
  const cookie = context.authCookies.sessionToken;
  return {
    baseURL: context.baseURL, optionURL: context.options.baseURL,
    origins: context.trustedOrigins, providers: context.trustedProviders,
    cookie: { name: cookie.name, secure: cookie.attributes.secure, domain: cookie.attributes.domain ?? null },
  };
}

export async function runDynamicContext(input: Input) {
  const events: Event[] = [];
  const barriers = new Map<string, { arrivals: Set<string>; ready: Promise<void>; release: () => void }>();
  async function rendezvous(stage: string, request?: Request) {
    if (!input.parallel || !request) return;
    const id = request.headers.get("x-probe-id");
    if (!id) throw new Error("Concurrent fixture requests require an ID");
    let barrier = barriers.get(stage);
    if (!barrier) {
      let release!: () => void;
      const ready = new Promise<void>(resolve => { release = resolve; });
      barrier = { arrivals: new Set(), ready, release }; barriers.set(stage, barrier);
    }
    barrier.arrivals.add(id);
    if (barrier.arrivals.size === input.calls.length) barrier.release();
    await barrier.ready;
  }
  function record(stage: string, request?: Request, baseURL?: string) {
    events.push({ stage, request: requestValue(request), ...(baseURL === undefined ? {} : { baseURL }) });
  }
  async function resolve(stage: "origins" | "providers", request?: Request) {
    record(stage, request);
    await rendezvous(stage, request);
    const failure = request?.headers.get("x-fail-trust");
    if (failure === `${stage}-api`) throw new APIError("BAD_REQUEST", { code: "TRUST_CALLBACK_REJECTED", message: `${stage} rejected` });
    if (failure === `${stage}-ordinary`) throw new Error(`${stage} failed`);
    const tenant = request?.headers.get("x-tenant");
    return stage === "origins"
      ? tenant ? [`https://${tenant}.frontend.test`] : ["https://initial.frontend.test"]
      : tenant ? [`${tenant}-provider`] : ["initial-provider"];
  }
  const inspect = async (ctx: any) => {
    const before = contextValue(ctx.context);
    record("endpoint", ctx.request, ctx.context.baseURL);
    await rendezvous("endpoint", ctx.request);
    return ctx.json({ before, after: contextValue(ctx.context), request: requestValue(ctx.request), headersTenant: ctx.headers?.get("x-tenant") ?? null });
  };
  const auth = betterAuth({
    baseURL: input.baseURL,
    basePath: input.basePath,
    secret: "dynamic-context-fixture-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, rateLimit: { enabled: false },
    advanced: {
      disableOriginCheck: false, trustedProxyHeaders: input.proxy,
      crossSubDomainCookies: { enabled: input.crossSubdomain },
      ...(input.defaultCookieDomain !== undefined ? { defaultCookieAttributes: { domain: input.defaultCookieDomain } } : {}),
      ...(input.sessionCookieDomain !== undefined ? { cookies: { session_token: { attributes: { domain: input.sessionCookieDomain } } } } : {}),
    },
    trustedOrigins: input.origins ?? ((request?: Request) => resolve("origins", request)),
    account: { accountLinking: { trustedProviders: input.providers ?? ((request?: Request) => resolve("providers", request)) } },
    plugins: [
      ...(input.pluginOrigins ?? []).map(source => ({
        id: source.id,
        init() {
          record(`init:${source.id}`);
          return { options: { trustedOrigins: source.dynamic ? async (request?: Request) => { record(`origins:${source.id}`, request); return source.values; } : source.values } };
        },
      })),
      {
        id: "dynamic-context-probe",
        onRequest: async (request: Request, context: any) => { record("onRequest", request, context.baseURL); },
        hooks: {
          before: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => { record("before", ctx.request, ctx.context.baseURL); }) }],
          after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => { record("after", ctx.request, ctx.context.baseURL); }) }],
        },
        endpoints: {
          dynamicProbe: createAuthEndpoint("/context-probe", { method: "GET" }, inspect),
          dynamicPost: createAuthEndpoint("/context-probe", { method: "POST" }, inspect),
        },
      },
    ],
  });
  let initialized: unknown;
  try { initialized = contextValue(await auth.$context); }
  catch (error) { return { initializationError: errorValue(error), events }; }
  const initEvents = events.splice(0);
  async function invoke(call: Call) {
    const eventStart = events.length;
    const method = call.method ?? "GET";
    const headers = new Headers(call.requestHeaders);
    headers.set("x-probe-id", call.id);
    if (method === "POST" && !headers.has("content-type")) headers.set("content-type", "application/json");
    const request = new Request(call.url ?? `https://a.tenant.test/api/auth/context-probe`, {
      method, headers, ...(method === "POST" ? { body: call.rawBody ?? "{}" } : {}),
    });
    let output: unknown;
    try {
      let value: any;
      if (call.transport === "http") value = await auth.handler(request);
      else {
        const endpoint = method === "POST" ? auth.api.dynamicPost : auth.api.dynamicProbe;
        value = await endpoint({
          ...(call.headers === undefined ? {} : { headers: new Headers({ ...call.headers, "x-probe-id": call.id }) }),
          ...(call.nativeRequest ? { request } : {}),
          ...(method === "POST" ? { body: {} } : {}),
          returnHeaders: true, returnStatus: true,
        });
      }
      if (value instanceof Response) {
        const raw = await value.text();
        output = { thrown: false, status: value.status, body: raw ? JSON.parse(raw) : null };
      } else output = { thrown: false, status: value.status ?? 200, body: value.response };
    } catch (error) { output = errorValue(error); }
    const observed = input.parallel ? events.filter(event => event.request?.id === call.id) : events.slice(eventStart);
    return { id: call.id, output, events: observed };
  }
  const calls = input.parallel ? await Promise.all(input.calls.map(invoke)) : [];
  if (!input.parallel) for (const call of input.calls) calls.push(await invoke(call));
  return { initialized, initEvents, calls, final: contextValue(await auth.$context) };
}

export function createDynamicContextFixture() {
  return { async handle(request: Request) {
    const path = new URL(request.url).pathname;
    if (["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
    if (path === "/__test/reset-state") return Response.json({ success: true });
    if (path === "/__test/dynamic-cookies") return Response.json(await runDynamicCookies());
    if (path === "/__test/dynamic-oauth") return Response.json(await runDynamicOAuth());
    if (path === "/__test/id-policy") return Response.json(await runIdPolicy(await request.json()));
    if (path === "/__test/dynamic-native") return Response.json(await runDynamicNative(await request.json()));
    if (path !== "/__test/dynamic-context") return new Response(null, { status: 404 });
    return Response.json(await runDynamicContext(await request.json()));
  } };
}
