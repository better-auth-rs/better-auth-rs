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

test("JSON HTTP output strips request headers while native output retains complete headers", async () => {
  const requestHeaders = [
    "host", "user-agent", "referer", "from", "expect", "authorization", "proxy-authorization",
    "cookie", "origin", "accept-charset", "accept-encoding", "accept-language", "if-match",
    "if-none-match", "if-modified-since", "if-unmodified-since", "if-range", "range", "max-forwards",
    "connection", "keep-alive", "transfer-encoding", "te", "upgrade", "trailer", "proxy-connection", "content-length",
  ];
  const safe = { accept: "application/example", "www-authenticate": "Example", "x-result": "preserved" };
  const supplied = { ...safe, ...Object.fromEntries(requestHeaders.map(name => [name, "1"])) };
  for (const failed of [false, true]) {
    for (const http of [false, true]) {
      const body = failed ? errorBody : { ok: true };
      const auth = betterAuth({
        baseURL: "http://header-contract.test", secret: "header-contract-secret-at-least-32-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        plugins: [{ id: "header-filter", endpoints: {
          headerFilter: createAuthEndpoint("/header-filter", { method: "GET" }, async ctx => {
            for (const [name, value] of Object.entries(supplied)) ctx.setHeader(name.toUpperCase(), value);
            ctx.setCookie("first", "1");
            ctx.setCookie("second", "2");
            if (failed) throw new APIError("BAD_REQUEST", errorBody);
            return ctx.json(body);
          }),
        } }],
      });
      let returned: any;
      let thrown: APIError | undefined;
      try {
        returned = await auth.api.headerFilter({ asResponse: http, returnHeaders: true });
      } catch (error) {
        expect(error).toBeInstanceOf(APIError);
        thrown = error as APIError;
      }
      expect(Boolean(thrown)).toBe(failed && !http);
      const resultHeaders = new Headers(thrown ? thrown[kAPIErrorHeaderSymbol] : returned.headers);
      expect(resultHeaders.getSetCookie()).toStrictEqual(["first=1", "second=2"]);
      resultHeaders.delete("set-cookie");
      expect(fields(resultHeaders)).toStrictEqual(http ? { ...safe, "content-type": "application/json" } : supplied);
      expect(http ? await returned.json() : thrown ? thrown.body : returned.response).toStrictEqual(body);
    }
  }
});

test("explicit Responses retain owned headers while queued headers merge only for HTTP", async () => {
  const headerValues = (input?: HeadersInit) => {
    const headers = new Headers(input);
    const cookies = headers.getSetCookie();
    headers.delete("set-cookie");
    return { entries: Object.fromEntries(headers), cookies };
  };
  const owned = {
    authorization: "owned credential", host: "owned.example", "x-result": "owned",
    "content-type": "application/explicit",
  };
  const ownedHeaders = { entries: owned, cookies: ["owned=1"] };
  for (const mode of ["before", "endpoint", "replace"]) {
    for (const overrideContentType of [false, true]) {
      for (const http of [false, true]) {
        const events: unknown[] = [];
        const queued = (phase: string) => ({
          origin: "queued.example", authorization: "queued credential", host: "queued.example",
          "x-result": phase, ...(overrideContentType ? { "content-type": "application/queued" } : {}),
        });
        const queue = (ctx: any, phase: string) => {
          for (const [name, value] of Object.entries(queued(phase))) ctx.setHeader(name, value);
          ctx.setCookie(phase, "1");
        };
        const explicit = () => new Response("explicit body", {
          status: 207, headers: { ...owned, "set-cookie": "owned=1" },
        });
        const observe = async (phase: string, ctx: any) => {
          const returned = ctx.context.returned;
          if (returned instanceof Response) expect(returned.status).toBe(207);
          events.push({
            phase, headers: headerValues(ctx.context.responseHeaders),
            owned: returned instanceof Response ? headerValues(returned.headers) : null,
            body: returned instanceof Response ? await returned.clone().text() : returned,
          });
        };
        const auth = betterAuth({
          baseURL: "http://header-contract.test", secret: "header-contract-secret-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false },
          hooks: {
            before: createAuthMiddleware(async ctx => {
              if (mode !== "before") return;
              queue(ctx, "before");
              return explicit();
            }),
            after: createAuthMiddleware(async ctx => {
              await observe("after", ctx);
              queue(ctx, "after");
              if (mode === "replace") return explicit();
            }),
          },
          plugins: [{
            id: "explicit-header-contract",
            endpoints: {
              explicitHeaderContract: createAuthEndpoint("/explicit-header-contract", { method: "GET" }, async ctx => {
                queue(ctx, "endpoint");
                return mode === "replace" ? ctx.json({ phase: "endpoint" }) : explicit();
              }),
            },
            hooks: { after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => {
              await observe("observer", ctx);
            }) }] },
          }],
        });
        const returned: any = await auth.api.explicitHeaderContract({ asResponse: http, returnHeaders: true });
        const response = http ? returned : returned.response;
        const phase = mode === "before" ? "before" : "after";
        const cookies = mode === "before" ? ["before=1"] : ["endpoint=1", "after=1"];
        expect(response).toBeInstanceOf(Response);
        expect(response.status).toBe(207);
        expect(await response.text()).toBe("explicit body");
        if (http) {
          expect(headerValues(response.headers)).toStrictEqual({
            entries: {
              ...owned, "x-result": phase,
              "content-type": overrideContentType ? "application/queued" : "application/explicit",
            },
            cookies: ["owned=1", ...cookies],
          });
        } else {
          expect(headerValues(returned.headers)).toStrictEqual({ entries: queued(phase), cookies });
          expect(headerValues(response.headers)).toStrictEqual(ownedHeaders);
        }
        expect(events).toStrictEqual(mode === "before" ? [] : [
          {
            phase: "after", headers: { entries: queued("endpoint"), cookies: ["endpoint=1"] },
            owned: mode === "replace" ? null : ownedHeaders,
            body: mode === "replace" ? { phase: "endpoint" } : "explicit body",
          },
          {
            phase: "observer", headers: { entries: queued("after"), cookies: ["endpoint=1", "after=1"] },
            owned: ownedHeaders, body: "explicit body",
          },
        ]);
      }
    }
  }
});
