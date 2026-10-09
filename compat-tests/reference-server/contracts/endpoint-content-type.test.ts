import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { admin, organization } from "better-auth/plugins";
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
        if (http) expect(returned.status).toBe(failed ? 400 : 200);
        else if (!failed) {
          expect(Object.hasOwn(returned, "status")).toBe(mode !== "before");
          expect(returned.status).toBeUndefined();
        }
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
        const returned: any = await auth.api.explicitHeaderContract({ asResponse: http, returnHeaders: true, returnStatus: true });
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
          expect(Object.hasOwn(returned, "status")).toBe(mode !== "before");
          expect(returned.status).toBeUndefined();
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

test("native status retains endpoint provenance across hook replacements", async () => {
  type Output = "json" | "response" | "return-error" | "throw-error";
  type Case = [string, Output | null, Output, 200 | 201 | undefined, Output | null, number | "undefined" | "absent", number];
  const cases: Case[] = [
    ["default-json", null, "json", undefined, null, "undefined", 200],
    ["set-200-json", null, "json", 200, null, 200, 200],
    ["set-201-json", null, "json", 201, null, 201, 201],
    ["default-response", null, "response", undefined, null, "undefined", 207],
    ["set-response", null, "response", 201, null, 201, 207],
    ["throw-error", null, "throw-error", undefined, null, 400, 400],
    ["set-throw-error", null, "throw-error", 201, null, 400, 400],
    ["return-error", null, "return-error", undefined, null, "undefined", 400],
    ["set-return-error", null, "return-error", 201, null, 201, 201],
    ["replace-json", null, "json", 201, "json", 201, 201],
    ["replace-response", null, "json", 201, "response", 201, 207],
    ["replace-return-error", null, "json", 201, "return-error", 201, 201],
    ["replace-throw-error", null, "json", 201, "throw-error", 201, 201],
    ["error-to-json", null, "throw-error", undefined, "json", 400, 400],
    ["error-to-response", null, "throw-error", undefined, "response", 400, 207],
    ["error-to-error", null, "throw-error", undefined, "throw-error", 400, 400],
    ["response-to-json", null, "response", undefined, "json", "undefined", 200],
    ["default-to-error", null, "json", undefined, "throw-error", "undefined", 409],
    ["returned-error-to-json", null, "return-error", undefined, "json", "undefined", 200],
    ["before-json", "json", "json", 201, null, "absent", 200],
    ["before-response", "response", "json", 201, null, "absent", 207],
    ["before-return-error", "return-error", "json", 201, null, "absent", 418],
    ["before-throw-error", "throw-error", "json", 201, null, "absent", 418],
  ];
  const returned = (kind: Output, phase: string, status: 400 | 409 | 418, ctx: any) => {
    if (kind === "json") return ctx.json({ phase });
    if (kind === "response") return new Response(phase, { status: 207 });
    const error = new APIError(status, { code: "STATUS_ERROR", message: phase });
    if (kind === "throw-error") throw error;
    return error;
  };
  const observation = async (value: any) => {
    if (value instanceof APIError) return { kind: "error", status: value.statusCode, body: value.body };
    if (value instanceof Response) return { kind: "response", status: value.status, body: await value.clone().text() };
    return { kind: "json", body: value };
  };
  const expectedObservation = (kind: Output, phase: string, status: number) => {
    if (kind === "json") return { kind: "json", body: { phase } };
    if (kind === "response") return { kind: "response", status: 207, body: phase };
    return { kind: "error", status, body: { code: "STATUS_ERROR", message: phase } };
  };
  for (const [name, before, endpoint, status, after, native, expectedHTTP] of cases) {
    for (const http of [false, true]) {
      const events: unknown[] = [];
      let retainedBefore: (() => void) | undefined;
      const auth = betterAuth({
        baseURL: "http://status-contract.test", secret: "status-contract-secret-at-least-32-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        hooks: {
          before: createAuthMiddleware(async ctx => {
            ctx.setStatus(202);
            retainedBefore = () => ctx.setStatus(205);
            if (before) return returned(before, "before", 418, ctx);
          }),
          after: createAuthMiddleware(async ctx => {
            events.push(await observation(ctx.context.returned));
            ctx.setStatus(203);
            if (after) return returned(after, "after", 409, ctx);
          }),
        },
        plugins: [{
          id: "status-contract",
          endpoints: { statusContract: createAuthEndpoint("/status-contract", { method: "GET" }, async ctx => {
            if (status !== undefined) ctx.setStatus(status);
            retainedBefore!();
            return returned(endpoint, "endpoint", 400, ctx);
          }) },
          hooks: { after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => {
            events.push(await observation(ctx.context.returned));
            ctx.setStatus(206);
          }) }] },
        }],
      });
      let result: any;
      let thrown: APIError | undefined;
      try {
        result = await auth.api.statusContract({ asResponse: http, returnHeaders: true, returnStatus: true });
      } catch (error) {
        expect(error, name).toBeInstanceOf(APIError);
        thrown = error as APIError;
      }
      const finalKind = before ?? after ?? endpoint;
      const failed = finalKind.endsWith("error");
      const shouldThrow = before === "throw-error" || (!http && before === null && failed);
      expect(Boolean(thrown), name).toBe(shouldThrow);
      const phase = before ? "before" : after ? "after" : "endpoint";
      const errorStatus = before ? 418 : after ? 409 : 400;
      if (thrown) {
        expect(thrown.statusCode, name).toBe(errorStatus);
        expect(thrown.body, name).toStrictEqual({ code: "STATUS_ERROR", message: phase });
      } else if (http) {
        expect(result.status, name).toBe(expectedHTTP);
        expect(finalKind === "response" ? await result.text() : await result.json(), name)
          .toStrictEqual(finalKind === "response" ? phase : failed ? { code: "STATUS_ERROR", message: phase } : { phase });
      } else {
        expect(Object.hasOwn(result, "status"), name).toBe(native !== "absent");
        expect(result.status, name).toBe(typeof native === "number" ? native : undefined);
        expect(await observation(result.response), name).toStrictEqual(expectedObservation(finalKind, phase, errorStatus));
      }
      expect(events, name).toStrictEqual(before ? [] : [
        expectedObservation(endpoint, "endpoint", 400),
        expectedObservation(finalKind, phase, after ? 409 : 400),
      ]);
    }
  }
});

test("native returned values retain identity and materialize by their actual type", async () => {
  const encode = (value: string) => [...new TextEncoder().encode(value)];
  const cases: [string, () => unknown, string, number[]][] = [
    ["undefined", () => undefined, "application/json", []],
    ["null", () => null, "application/json", encode("null")],
    ["false", () => false, "application/json", encode("false")],
    ["true", () => true, "application/json", encode("true")],
    ["zero", () => 0, "application/json", encode("0")],
    ["negative-zero", () => -0, "application/json", encode("0")],
    ["number", () => 1.25, "application/json", encode("1.25")],
    ["nan", () => NaN, "application/json", encode("NaN")],
    ["infinity", () => Infinity, "application/json", encode("null")],
    ["negative-infinity", () => -Infinity, "application/json", encode("null")],
    ["empty-string", () => "", "application/json", []],
    ["string", () => "hello 中", "text/plain", encode("hello 中")],
    ["utf16", () => "\ud800A\udc00", "text/plain", encode("�A�")],
    ["array", () => [undefined, NaN, new Date(0)], "application/json", encode('[null,null,"1970-01-01T00:00:00.000Z"]')],
    ["object", () => ({ value: "hello", omitted: undefined }), "application/json", encode('{"value":"hello"}')],
    ["date", () => new Date(0), "application/json", encode('"1970-01-01T00:00:00.000Z"')],
    ["invalid-date", () => new Date(NaN), "application/json", encode("null")],
    ["binary", () => new Uint8Array([0, 255, 65]), "application/octet-stream", [0, 255, 65]],
    ["array-buffer", () => new Uint8Array([0, 255, 65]).buffer, "application/octet-stream", [0, 255, 65]],
    ["binary-view", () => new Uint8Array([9, 0, 255, 65, 9]).subarray(1, 4), "application/octet-stream", [0, 255, 65]],
    ["blob", () => new Blob([new Uint8Array([0, 255, 65])], { type: "IMAGE/PNG" }), "image/png", [0, 255, 65]],
    ["blob-json-type", () => new Blob([new Uint8Array([0, 255, 65])], { type: "APPLICATION/JSON" }), "application/json", [0, 255, 65]],
    ["blob-empty-type", () => new Blob([new Uint8Array([0, 255, 65])]), "application/octet-stream", [0, 255, 65]],
    ["blob-invalid-type", () => new Blob([new Uint8Array([0, 255, 65])], { type: "text/中" }), "application/octet-stream", [0, 255, 65]],
    ["response", () => new Response("explicit", { status: 207, headers: { "content-type": "text/plain" } }), "text/plain", encode("explicit")],
    ["html", () => new Response("<p>explicit</p>", { status: 207, headers: { "content-type": "text/html; charset=utf-8" } }), "text/html; charset=utf-8", encode("<p>explicit</p>")],
  ];
  for (const [name, create, contentType, bytes] of cases) {
    for (const phase of ["endpoint", "before", "after"]) {
      for (const http of [false, true]) {
        const value = create();
        const fallback = { endpoint: true };
        const observed: unknown[] = [];
        const queue = (ctx: any, name: string) => {
          ctx.setHeader(name, "1");
          ctx.setHeader("authorization", "queued");
          ctx.setHeader("content-type", "application/queued");
        };
        const auth = betterAuth({
          baseURL: "http://value-contract.test", secret: "value-contract-secret-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false },
          hooks: {
            before: createAuthMiddleware(async ctx => {
              if (phase === "before") { queue(ctx, "x-before"); return value; }
            }),
            after: createAuthMiddleware(async ctx => {
              observed.push(ctx.context.returned);
              ctx.setHeader("x-after", "1");
              if (phase === "after") return value;
            }),
          },
          plugins: [{
            id: "value-contract",
            endpoints: { valueContract: createAuthEndpoint("/value-contract", { method: "GET" }, async ctx => {
              ctx.setStatus(201);
              queue(ctx, "x-endpoint");
              return ctx.json(phase === "endpoint" ? value : fallback);
            }) },
            hooks: { after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => { observed.push(ctx.context.returned); }) }] },
          }],
        });
        const result: any = await auth.api.valueContract({ asResponse: http, returnHeaders: true, returnStatus: true });
        const short = phase === "before" && value !== null && typeof value === "object";
        const ignored = phase === "before" && !short || phase === "after" && value === undefined;
        const expected = ignored ? fallback : value;
        const explicit = expected instanceof Response;
        expect(observed.length, `${name}/${phase}`).toBe(short ? 0 : 2);
        if (!short) { expect(Object.is(observed[0], phase === "endpoint" ? value : fallback)).toBe(true); expect(Object.is(observed[1], expected)).toBe(true); }
        const headers = new Headers(result.headers);
        expect(headers.has("x-before")).toBe(short);
        expect(headers.has("x-after")).toBe(!short);
        expect(headers.has("x-endpoint")).toBe(!short);
        if (http) {
          expect(result.status).toBe(explicit ? 207 : short ? 200 : 201);
          expect(headers.has("authorization")).toBe(false);
          expect(headers.get("content-type")).toBe(explicit ? "application/queued" : ignored ? "application/json" : contentType);
          expect([...new Uint8Array(await result.arrayBuffer())]).toStrictEqual(ignored ? encode('{"endpoint":true}') : bytes);
        } else {
          expect(Object.is(result.response, expected)).toBe(true);
          expect(Object.hasOwn(result, "status")).toBe(!short);
          expect(result.status).toBe(short ? undefined : 201);
          expect(headers.get("authorization")).toBe("queued");
          expect(headers.get("content-type")).toBe("application/queued");
          if (explicit) expect(expected.headers.get("content-type")).toBe(contentType);
        }
      }
    }
  }
});

test("HTTP materialization distinguishes an absent body from an empty string", async () => {
  for (const status of [204, 205, 304]) {
    for (const value of [undefined, null, "", false, 0]) {
      const auth = betterAuth({
        baseURL: "http://value-contract.test", secret: "value-contract-secret-at-least-32-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        plugins: [{ id: "empty-contract", endpoints: { emptyContract: createAuthEndpoint("/empty-contract", { method: "GET" }, async ctx => { ctx.setStatus(status); return value; }) } }],
      });
      if (value === undefined) { const response = await auth.api.emptyContract({ asResponse: true }); expect(response.status).toBe(status); expect(response.body).toBeNull(); }
      else await expect(auth.api.emptyContract({ asResponse: true })).rejects.toBeInstanceOf(TypeError);
    }
  }
});

test("update-session rejects invalid updates as native API errors and HTTP 400", async () => {
  const now = new Date();
  const session = {
    user: { id: "owner", email: "owner@status.test", emailVerified: true, name: "Owner", createdAt: now, updatedAt: now },
    session: { id: "session", userId: "owner", token: "token", createdAt: now, updatedAt: now, expiresAt: new Date("2099-01-01") },
  };
  const auth = betterAuth({
    baseURL: "http://status-contract.test", secret: "status-contract-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [organization({ teams: { enabled: true } }), admin()],
    hooks: { before: createAuthMiddleware(async ctx => { ctx.context.session = session; }) },
  });
  for (const field of [undefined, "unknown", "activeOrganizationId", "activeTeamId", "impersonatedBy"]) {
    const body = field ? { [field]: "forbidden" } : {};
    const expected = field && field !== "unknown"
      ? { code: "FIELD_NOT_ALLOWED", message: `${field} is not allowed to be set` }
      : { message: "No fields to update" };
    let caught: APIError | undefined;
    try { await auth.api.updateSession({ body, returnStatus: true, returnHeaders: true }); }
    catch (error) { expect(error).toBeInstanceOf(APIError); caught = error as APIError; }
    expect(caught?.statusCode).toBe(400);
    expect(caught?.body).toStrictEqual(expected);
    const response = await auth.api.updateSession({ body, asResponse: true });
    expect(response.status).toBe(400);
    expect(await response.json()).toStrictEqual(expected);
    expect(session.session).toStrictEqual({ id: "session", userId: "owner", token: "token", createdAt: now, updatedAt: now, expiresAt: new Date("2099-01-01") });
  }
});
