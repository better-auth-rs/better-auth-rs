import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

const tolerant = process.env.COMPAT_PROFILE === "trailing-slashes-true";
async function request(ctx: any, path: string, method: string) {
  await fetch(`${ctx.baseURL}/__test/trailing-slashes`, { method: "POST" });
  const response = await fetch(`${ctx.baseURL}${path}`, {
    method, redirect: "manual", ...(method === "POST" ? { headers: { "content-type": "application/json" }, body: JSON.stringify({ proof: "post" }) } : {}),
  });
  const text = await response.text();
  const result = { status: response.status, location: response.headers.get("location"), body: text ? (() => { try { return JSON.parse(text); } catch { return text; } })() : "" };
  const { events } = await (await fetch(`${ctx.baseURL}/__test/trailing-slashes`)).json();
  return { result, events };
}

function expectSuccess(value: any, url: string, method: string, endpointPath: string, params: object = {}, query: object = {}) {
  const event = { path: endpointPath, url, method, params };
  expect(value.result).toEqual({ status: 200, location: null, body: { phase: "endpoint", ...event, body: method === "POST" ? { proof: "post" } : null, query } });
  expect(value.events).toEqual([
    { phase: "http", url, method }, { phase: "before", ...event }, { phase: "endpoint", ...event },
    { phase: "after", ...event }, { phase: "response", status: 200 },
  ]);
}

function expectRouterMiss(value: any, url: string, method: string) {
  expect(value.result).toEqual({ status: 404, location: null, body: "" });
  expect(value.events).toEqual([{ phase: "http", url, method }, { phase: "response", status: 404 }]);
}

compatScenario("trailing slash tolerance matches declaration and preserves HTTP method", async ctx => {
  const observations: unknown[] = [];
  for (const method of ["GET", "POST"]) {
    for (const [suffix, endpointPath, exact] of [
      ["/probe", "/probe", true], ["/probe/", "/probe", false],
      ["/declared/", "/declared/", true], ["/declared", "/declared/", false],
      ["/", "/", true],
    ] as const) {
      const url = `/api/auth${suffix}`;
      const result = await request(ctx, url, method);
      if (exact || tolerant) expectSuccess(result, url, method, endpointPath);
      else expectRouterMiss(result, url, method);
      observations.push({ url, method, ...result });
    }
    for (const url of ["/api/auth", "/probe", "/declared/", "/api/auth/probe//", "/api/auth//probe", "/api/auth/probe//child", "/api//auth/probe", "/api/authentication/probe"]) {
      const result = await request(ctx, url, method);
      expectRouterMiss(result, url, method);
      observations.push({ url, method, ...result });
    }
  }
  return observations;
});

compatScenario("disabled paths trim request slashes before routing and before HTTP hooks", async ctx => {
  const observations: unknown[] = [];
  for (const method of ["GET", "POST"]) {
    for (const suffix of ["/disabled", "/disabled/", "/disabled//", "/disabled-declared", "/disabled-declared/", "/dynamic/blocked", "/dynamic/blocked/"]) {
      const url = `/api/auth${suffix}?proof=unchanged`;
      const result = await request(ctx, url, method);
      expect(result).toEqual({ result: { status: 404, location: null, body: "Not Found" }, events: [] });
      observations.push({ url, method, ...result });
    }
    for (const suffix of ["/disabled-slash-config", "/disabled-slash-config/"]) {
      const url = `/api/auth${suffix}`;
      const result = await request(ctx, url, method);
      if (!suffix.endsWith("/") || tolerant) expectSuccess(result, url, method, "/disabled-slash-config");
      else expectRouterMiss(result, url, method);
      observations.push({ url, method, ...result });
    }
  }
  return observations;
});

compatScenario("dynamic endpoint paths use their declaration while Request URL retains its trailing slash", async ctx => {
  const observations: unknown[] = [];
  for (const method of ["GET", "POST"]) {
    for (const suffix of ["/dynamic/alpha", "/dynamic/alpha/"]) {
      const url = `/api/auth${suffix}?value=one`;
      const result = await request(ctx, url, method);
      if (!suffix.endsWith("/") || tolerant) expectSuccess(result, url, method, "/dynamic/:id", { id: "alpha" }, { value: "one" });
      else expectRouterMiss(result, url, method);
      observations.push({ url, method, ...result });
    }
    const url = "/api/auth/dynamic/alpha//?value=one";
    const result = await request(ctx, url, method);
    expectRouterMiss(result, url, method);
    observations.push({ url, method, ...result });
  }
  return observations;
});

compatScenario("HTTP response hooks skip early replies and stop after a replacement", async ctx => {
  const observations = [];
  for (const method of ["GET", "POST"]) {
    const early = await request(ctx, "/api/auth/early", method);
    expect(early).toEqual({ result: { status: 202, location: null, body: { early: true } }, events: [
      { phase: "http", url: "/api/auth/early", method },
    ] });
    const replacement = await request(ctx, "/api/auth/replace-response", method);
    expect(replacement.result).toEqual({ status: 202, location: null, body: { replaced: true } });
    expect(replacement.events.map((event: any) => event.phase)).toEqual(["http", "before", "endpoint", "after", "response"]);
    observations.push({ early, replacement });
  }
  await fetch(`${ctx.baseURL}/__test/trailing-slashes`, { method: "POST" });
  const chain = await fetch(`${ctx.baseURL}/api/auth/response-chain`);
  const chainResult = { status: chain.status, header: chain.headers.get("x-response-chain"), body: await chain.json() };
  const { events: chainEvents } = await (await fetch(`${ctx.baseURL}/__test/trailing-slashes`)).json();
  expect(chainResult.status).toBe(200);
  expect(chainResult.header).toBe("second");
  expect(chainEvents.map((event: any) => event.phase)).toEqual(["http", "before", "endpoint", "after", "response", "later-response"]);
  expect(chainEvents.at(-1)).toEqual({ phase: "later-response", header: "first" });
  observations.push({ chainResult, chainEvents });
  for (const [contentType, body, status, error] of [
    ["application/json", "{", 400, { code: "BAD_REQUEST", message: "Invalid JSON in request body" }],
    ["text/plain", "plain", 415, { code: "UNSUPPORTED_MEDIA_TYPE", message: 'Content-Type "text/plain" is not allowed. Allowed types: application/json' }],
  ] as const) {
    await fetch(`${ctx.baseURL}/__test/trailing-slashes`, { method: "POST" });
    const response = await fetch(`${ctx.baseURL}/api/auth/probe`, { method: "POST", headers: { "content-type": contentType }, body });
    const result = { status: response.status, body: await response.json() };
    const { events } = await (await fetch(`${ctx.baseURL}/__test/trailing-slashes`)).json();
    expect(result).toEqual({ status, body: error });
    expect(events).toEqual([
      { phase: "http", url: "/api/auth/probe", method: "POST" }, { phase: "response", status },
    ]);
    observations.push({ result, events });
  }
  return observations;
});
