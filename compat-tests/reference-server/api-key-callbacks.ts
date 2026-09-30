import { APIError, isAPIError } from "better-auth/api";
import type { ApiKeyOptions } from "@better-auth/api-key";

export function createApiKeyCallbacks(profile: string) {
  let events: unknown[] = [];
  let control: Record<string, any> = {};
  const cache = new Map<string, string>();
  const storage = {
    async get(key: string) { return cache.get(key) ?? null; },
    async set(key: string, value: string) { cache.set(key, value); },
    async delete(key: string) { cache.delete(key); },
  };
  let counter = 0;
  let gets = 0;
  const reset = () => { events = []; control = {}; counter = 0; gets = 0; cache.clear(); };
  const fail = (kind: string) => {
    if (control[`${kind}Mode`] === "api-error") throw APIError.from("FORBIDDEN", { code: "CALLBACK_REJECTED", message: "Callback rejected" });
    if (control[`${kind}Mode`] === "error") throw new Error("Callback failed");
  };
  function options(configId: string): ApiKeyOptions {
    return {
      configId, defaultKeyLength: 12, defaultPrefix: "generated_", enableMetadata: true,
      rateLimit: { enabled: false },
      startingCharactersConfig: { shouldStore: configId !== "no-start", charactersLength: 6 },
      ...(configId === "callback-cache" ? { storage: "secondary-storage" as const, customStorage: storage } : {}),
      enableSessionForAPIKeys: configId === "callback-session",
      ...(configId === "callback-session" ? { customAPIKeyGetter: (ctx: any) => {
        gets += 1;
        events.push({ event: "get", path: ctx.path ?? null, hasRequest: Boolean(ctx.request) });
        fail("getter");
        if (control.getterMode === "second-error" && gets % 2 === 0) throw new Error("Callback failed");
        if (control.getterMode === "second-api-error" && gets % 2 === 0) throw APIError.from("FORBIDDEN", { code: "CALLBACK_REJECTED", message: "Callback rejected" });
        if (control.getterMode === "none" || (control.getterMode === "second-none" && gets % 2 === 0)) return null;
        return control.nativeKey ?? ctx.headers?.get("x-callback-key") ?? null;
      } } : {}),
      customKeyGenerator: async ({ length, prefix }) => {
        await Promise.resolve();
        events.push({ event: "generate", configId, length, prefix: prefix ?? null });
        fail("generator");
        if (typeof control.generatedKey === "string") return control.generatedKey;
        return `${prefix ?? ""}custom_${++counter}_${"k".repeat(length)}`;
      },
      customAPIKeyValidator: async ({ key, ctx }) => {
        await Promise.resolve();
        events.push({ event: "validate", configId, key, path: ctx.path ?? null, hasRequest: Boolean(ctx.request) });
        fail("validator");
        return control.validatorMode !== "deny";
      },
      permissions: { defaultPermissions: async (referenceId, ctx) => {
        await Promise.resolve();
        events.push({ event: "permissions", configId, referenceId, path: ctx.path ?? null,
          hasRequest: Boolean(ctx.request), name: ctx.body.name ?? null,
          expiresIn: ctx.body.expiresIn, remaining: ctx.body.remaining,
        });
        fail("permissions");
        return { nodes: [ctx.body.name === "Native" ? "native" : "read"] };
      } },
    };
  }
  return {
    configurations: profile === "api-key-callbacks" ? [options("default"), options("named"), options("callback-session"), options("callback-cache"), options("no-start")] : null,
    reset,
    async route(request: Request, auth: any): Promise<Response | null> {
      const path = new URL(request.url).pathname;
      if (path === "/__test/api-key-callbacks/control") {
        if (request.method === "POST") {
          const body = await request.json();
          control = { ...control, ...body };
          if (body.clear !== false) { events = []; gets = 0; }
        }
        return Response.json({ events });
      }
      if (path !== "/__test/api-key-callbacks/call") return null;
      const { operation, input } = await request.json();
      try {
        const result = await auth.api[operation === "create" ? "createApiKey" : operation === "update" ? "updateApiKey" : "verifyApiKey"]({ body: input });
        return Response.json({ kind: "result", result });
      } catch (error) {
        if (isAPIError(error)) return Response.json({ kind: "thrown", status: error.statusCode, body: error.body });
        return Response.json({ kind: "error", message: (error as Error).message });
      }
    },
  };
}
