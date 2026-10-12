import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { createInternalContext } from "../node_modules/better-call/dist/context.mjs";
import { dispatchAuthEndpoint } from "../node_modules/better-auth/dist/api/dispatch.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver } from "./secondary-native-shared.mjs";

const baseURL = "http://native-endpoint-context.test";
const secret = "native-endpoint-context-contract-at-least-32-characters";

function source(path) {
  return { path, sha256: createHash("sha256").update(readFileSync(new URL(path, import.meta.url))).digest("hex") };
}

async function construction(name, input, options = { method: "POST" }) {
  const observer = createSecondaryNativeObserver();
  const context = await createInternalContext(input, { options, path: "/native-context" });
  const graph = observer.snapshot({ input, context });
  const descriptor = Object.getOwnPropertyDescriptor(context, "responseStatus");
  assert.equal(typeof descriptor.get, "function");
  assert.equal(descriptor.set, undefined);
  assert.equal(context.responseStatus, undefined);
  const status = { native: name };
  context.setStatus(status);
  assert.equal(context.responseStatus, status);
  assert.equal(Reflect.set(context, "responseStatus", 201), false);
  assert.equal(context.responseStatus, status);
  return { name, graph, changed: observer.snapshot({ context, status }), functions: observer.functions };
}

async function helpers(asResponse) {
  const observer = createSecondaryNativeObserver();
  const originalHeaders = new Headers({ "x-original": "retained", cookie: "plain=original; __Host-prefixed=host" });
  const body = { ownUndefined: undefined };
  const input = { headers: originalHeaders, asResponse, body };
  const context = await createInternalContext(input, { options: { method: "POST" }, path: "/helpers" });
  const before = observer.snapshot({ input, context });
  const { getHeader, getCookie, setHeader, setCookie, setSignedCookie, setStatus, json, redirect, error } = context;
  context.headers = new Headers({ "x-original": "replacement", cookie: "plain=replacement" });
  originalHeaders.set("x-original", "mutated-original");
  originalHeaders.set("cookie", "plain=mutated-original");
  assert.equal(getHeader("x-original"), "mutated-original");
  assert.equal(getCookie("plain"), "original");
  assert.equal(getCookie("prefixed", "host"), "host");
  setHeader("X-Result", "first");
  setHeader("x-result", "second");
  const cookie = setCookie("result", "one", { path: "/", httpOnly: true });
  const signedCookie = await setSignedCookie("signed", "payload", secret, { path: "/" });
  const status = { code: 202 };
  setStatus(status);
  const routerResponse = { body: { replaced: true }, status: 203 };
  const jsonResult = json(body, routerResponse);
  assert.equal(asResponse ? jsonResult.body : jsonResult, asResponse ? routerResponse.body : body);
  const redirected = redirect("/next");
  assert.equal(redirected.headers, context.responseHeaders);
  const failureBody = { native: true };
  const failureHeaders = new Headers({ "x-failure": "kept" });
  const failure = error("CONFLICT", failureBody, failureHeaders);
  assert.equal(failure.body, failureBody);
  assert.equal(failure.headers, failureHeaders);
  const signed = await createInternalContext({ headers: { cookie: signedCookie.split(";")[0] } }, { options: { method: "GET" }, path: "/signed" });
  assert.equal(await signed.getSignedCookie("signed", secret), "payload");
  assert.equal(await signed.getSignedCookie("signed", "different-secret"), false);
  return {
    name: `helpers-as-response-${asResponse}`, before,
    changed: observer.snapshot({ input, context, status, body, routerResponse, jsonResult, failureBody, failureHeaders }),
    requestHeaders: [...originalHeaders], replacementHeaders: [...context.headers],
    responseHeaders: [...context.responseHeaders], cookies: context.responseHeaders.getSetCookie(), cookie, signedCookie,
    redirect: { status: redirected.status, statusCode: redirected.statusCode, sameHeaders: redirected.headers === context.responseHeaders },
    error: { status: failure.status, statusCode: failure.statusCode, sameBody: failure.body === failureBody, sameHeaders: failure.headers === failureHeaders },
    functions: observer.functions,
  };
}

async function dispatch() {
  const observer = createSecondaryNativeObserver();
  const database = { user: [], session: [], account: [], verification: [] };
  const roots = [];
  const observations = [];
  const body = { marker: "body", ownUndefined: undefined };
  const options = {
    baseURL, secret, database: memoryAdapter(database), logger: { disabled: true }, telemetry: { enabled: false },
    rateLimit: { enabled: false }, advanced: { disableOriginCheck: false },
    hooks: {
      before: createAuthMiddleware(async context => {
        roots.push(context);
        observations.push({ phase: "before", graph: observer.snapshot(context) });
        assert.equal(context.body, body);
        context.setHeader("x-before", "before");
      }),
      after: createAuthMiddleware(async context => {
        roots.push(context);
        observations.push({ phase: "after", graph: observer.snapshot(context) });
        assert.equal(context.body, body);
        context.setHeader("x-after", "after");
      }),
    },
  };
  const runtime = await betterAuth(options).$context;
  const initial = observer.snapshot(runtime);
  const endpoint = createAuthEndpoint("/context-probe", { method: "POST" }, async context => {
    roots.push(context);
    observations.push({ phase: "handler", graph: observer.snapshot(context) });
    assert.equal(context.body, body);
    context.setHeader("x-handler", "handler");
    context.setStatus(201);
    return context.json(body);
  });
  const input = { context: runtime, body, query: { marker: "query" }, headers: { "x-input": "input" }, returnHeaders: true, returnStatus: true };
  const result = await dispatchAuthEndpoint(endpoint, input);
  assert.deepEqual(observations.map(value => value.phase), ["before", "handler", "after"]);
  assert.equal(result.response, body);
  assert.equal(result.status, 201);
  const [before, handler, after] = roots;
  assert.notEqual(before, handler);
  assert.notEqual(handler, after);
  assert.equal(before.context, handler.context);
  assert.equal(handler.context, after.context);
  assert.notEqual(handler.context, runtime);
  assert.equal(handler.context.options, runtime.options);
  const session = { session: { id: "session" }, user: { id: "user" } };
  const receiver = { newSession: null, trustedOrigins: ["https://receiver.test"] };
  runtime.setNewSession.call(receiver, session);
  assert.equal(receiver.newSession, session);
  assert.equal(runtime.newSession, null);
  assert.equal(runtime.isTrustedOrigin.call(receiver, "https://receiver.test/path"), true);
  assert.equal(runtime.isTrustedOrigin.call(receiver, baseURL), false);
  assert.deepEqual(database, { user: [], session: [], account: [], verification: [] });
  return {
    name: "dispatcher-roots", initial, observations,
    retained: observer.snapshot({ input, roots, result, receiver, session }),
    responseHeaders: [...result.headers], storage: database, functions: observer.functions,
  };
}

export async function captureNativeEndpointContext() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/memory-adapter"]);
  const cases = [await construction("omitted", {})];
  for (const [name, context] of [["undefined", undefined], ["null", null], ["false", false], ["zero", 0], ["number", 7], ["string", "runtime"], ["object", { marker: true }]]) {
    cases.push(await construction(`inner-${name}`, { context }));
  }
  cases.push(await helpers(false), await helpers(true), await dispatch());
  return {
    version: "1.7.6", runtime: { bun: Bun.version },
    sources: [source("../node_modules/better-call/dist/context.mjs"), source("../node_modules/better-auth/dist/api/dispatch.mjs"), source("../node_modules/better-auth/dist/context/create-context.mjs")],
    boundary: "Complete own-property descriptors and reachable helper identities. Native Headers entries are recorded separately. Prototype graphs and other host internal slots are not projected.",
    cases,
  };
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureNativeEndpointContext(), null, 2)}\n`;
  assert.ok(process.argv[2], "Pass the endpoint context capture output path");
  writeFileSync(process.argv[2], serialized);
}
