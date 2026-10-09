import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { APIError, kAPIErrorHeaderSymbol } from "better-call";

const errorBody = { code: "FIXTURE_ERROR", message: "fixture rejection" };
const fields = (headers?: HeadersInit) => Object.fromEntries(new Headers(headers));

test("JSON headers materialize after endpoint hooks and preserve explicit native headers", async () => {
  for (const mode of ["before", "endpoint", "replace", "replace-json", "endpoint-error", "after-error", "before-error"]) {
    for (const contentType of [undefined, "application/json", "application/problem+json"]) {
      for (const http of [false, true]) {
        if (http && mode === "before-error") continue;
        const events: unknown[] = [];
        const explicit = () => ({ "x-error": "1", ...(contentType ? { "content-type": contentType } : {}) });
        const observe = (phase: string, ctx: any) => events.push({
          phase, headers: fields(ctx.context.responseHeaders),
          body: ctx.context.returned instanceof APIError ? ctx.context.returned.body : ctx.context.returned,
        });
        const auth = betterAuth({
          baseURL: "http://header-contract.test", secret: "header-contract-secret-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false },
          hooks: {
            before: createAuthMiddleware(async ctx => {
              if (mode !== "before" && mode !== "before-error") return;
              ctx.setHeader("x-before", "1");
              if (mode === "before-error") throw new APIError("BAD_REQUEST", errorBody, explicit());
              if (contentType) ctx.setHeader("CoNtEnT-TyPe", contentType);
              return ctx.json({ phase: "before" });
            }),
            after: createAuthMiddleware(async ctx => {
              observe("after", ctx);
              ctx.setHeader("x-after", "1");
              if (mode === "after-error") throw new APIError("BAD_REQUEST", errorBody, { "x-error": "1" });
              if (mode === "replace" || mode === "replace-json") {
                ctx.setHeader("x-replacement", "1");
                return ctx.json({ phase: "after" });
              }
            }),
          },
          plugins: [{
            id: "header-contract",
            endpoints: { headerContract: createAuthEndpoint("/header-contract", { method: "GET" }, async ctx => {
              ctx.setHeader("x-endpoint", "1");
              if (mode === "endpoint-error") throw new APIError("BAD_REQUEST", errorBody, explicit());
              if (contentType) ctx.setHeader("CoNtEnT-TyPe", contentType);
              return ctx.json({ phase: "endpoint" });
            }) },
            hooks: { after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => { observe("observer", ctx); }) }] },
          }],
        });
        let thrown: APIError | undefined;
        let returned: any;
        try {
          returned = await auth.api.headerContract({ asResponse: http, returnHeaders: true, returnStatus: true });
        } catch (error) {
          expect(error).toBeInstanceOf(APIError);
          thrown = error as APIError;
        }
        const failed = mode.endsWith("error");
        expect(Boolean(thrown)).toBe(failed && !http);
        const expectedBody = failed ? errorBody : { phase: mode === "before" ? "before" : mode.startsWith("replace") ? "after" : "endpoint" };
        const expectedHeaders: Record<string, string> = contentType ? { "content-type": contentType } : {};
        if (mode === "before") expectedHeaders["x-before"] = "1";
        else if (mode !== "before-error") Object.assign(expectedHeaders, { "x-endpoint": "1", "x-after": "1" });
        if (failed) expectedHeaders["x-error"] = "1";
        if (mode.startsWith("replace")) expectedHeaders["x-replacement"] = "1";
        const nativeHeaders = { ...expectedHeaders };
        if (http) expectedHeaders["content-type"] = "application/json";
        const actualHeaders = http ? returned.headers : thrown ? mode === "before-error" ? thrown.headers : thrown[kAPIErrorHeaderSymbol] : returned.headers;
        expect(fields(actualHeaders)).toStrictEqual(expectedHeaders);
        expect(http ? await returned.json() : thrown ? thrown.body : returned.response).toStrictEqual(expectedBody);
        if (mode.startsWith("before")) expect(events).toStrictEqual([]);
        else {
          const initial: Record<string, string> = { "x-endpoint": "1", ...(contentType ? { "content-type": contentType } : {}) };
          if (mode === "endpoint-error") initial["x-error"] = "1";
          expect(events).toStrictEqual([
            { phase: "after", headers: initial, body: mode === "endpoint-error" ? errorBody : { phase: "endpoint" } },
            { phase: "observer", headers: nativeHeaders, body: expectedBody },
          ]);
        }
        if (thrown) {
          expect(fields(thrown.headers)).toStrictEqual(mode === "after-error" ? { "x-error": "1" } : explicit());
          expect(fields(thrown[kAPIErrorHeaderSymbol])).toStrictEqual(mode === "before-error" ? { "x-before": "1" } : nativeHeaders);
        }
      }
    }
  }
});
