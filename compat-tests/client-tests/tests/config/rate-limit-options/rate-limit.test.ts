import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
async function configure(ctx: Context, config: unknown) {
  const result = await ctx.rawRequest({ path: "/__test/rate-limit", method: "POST", json: { config, clearEvents: true } });
  expect(result.status).toBe(200);
}
async function snapshot(ctx: Context) {
  const result = await ctx.rawRequest({ path: "/__test/rate-limit" });
  expect(result.status).toBe(200);
  return result.body as { events: any[]; rows: { key: string; count: number }[] };
}
async function request(ctx: Context, ip: string, path = "/api/limits/ok") {
  const response = await ctx.actor().fetch(path, { headers: { "x-forwarded-for": ip } });
  return { status: response.status, retry: response.headers.get("x-retry-after"), contentType: response.headers.get("content-type"), body: await response.json() };
}

compatScenario("rate limit selects the first plugin and custom rule and forwards the normalized key", async ctx => {
  const results = [];
  for (const [policy, path, window, maximum] of [
    ["none", "/api/limits/sign-in-extra///?probe=one", "10", "3"],
    ["none", "/api/limits/request-password-reset", "60", "3"],
    ["plugins", "/api/limits/ok///?probe=two", "21", "4"],
    ["first", "/api/limits/ok?probe=three", "7.5", "1.5"],
    ["unchanged", "/api/limits/ok", "21", "4"],
  ]) {
    await configure(ctx, { backend: "database", custom: true, policy });
    const response = await request(ctx, "192.0.2.10", path);
    expect(response.status).toBe(429);
    expect(response.retry).toBe(window);
    expect(response.body).toEqual({ message: "Too many requests. Please try again later." });
    const state = await snapshot(ctx);
    expect(state.rows).toEqual([]);
    const consume = state.events.at(-1);
    expect(consume).toEqual({ kind: "consume", key: `192.0.2.10|${new URL(path!, ctx.baseURL).pathname.replace("/api/limits", "").replace(/\/+$/, "")}`, window, max: maximum });
    expect(state.events.filter(event => event.kind === "matcher").every(event => event.index === 0)).toBe(true);
    if (policy === "first" || policy === "unchanged") expect(state.events.find(event => event.kind === "rule")).toEqual({ kind: "rule", path, window: "21", max: "4" });
    results.push({ response, state });
  }
  await configure(ctx, { backend: "database", custom: true, policy: "disabled" });
  const disabled = await request(ctx, "192.0.2.10");
  expect(disabled.status).toBe(200);
  const state = await snapshot(ctx);
  expect(state.events.map(event => event.kind)).toEqual(["matcher", "rule"]);
  return { results, disabled, state };
});

compatScenario("rate limit backend precedence preserves explicit memory and secondary capability failures", async ctx => {
  const results = [];
  for (const backend of ["auto", "secondary", "memory"]) {
    await configure(ctx, { backend, secondary: true, policy: "numeric", window: "2.5", max: "1" });
    const ip = backend === "auto" ? "192.0.2.20" : backend === "secondary" ? "192.0.2.21" : "192.0.2.22";
    const first = await request(ctx, ip);
    const second = await request(ctx, ip);
    expect([first.status, second.status]).toEqual([200, 429]);
    expect(second.retry).toBe(backend === "memory" ? "3" : "2.5");
    const state = await snapshot(ctx);
    expect(state.events).toEqual(backend === "memory" ? [] : Array.from({ length: 2 }, () => ({ kind: "increment", key: `${ip}|/ok`, ttl: "2.5" })));
    results.push({ first, second, state });
  }
  await configure(ctx, { backend: "missing" });
  // The hosting runtime owns the representation of an unhandled storage error.
  const missing = await fetch(`${ctx.baseURL}/api/limits/ok`, { headers: { "x-forwarded-for": "192.0.2.23" } });
  expect(missing.status).toBe(500);
  await missing.text();
  await configure(ctx, { backend: "missing", disabledIp: true });
  const disabled = await request(ctx, "192.0.2.23");
  expect(disabled.status).toBe(200);
  await configure(ctx, { backend: "missing", custom: true });
  const overridden = await request(ctx, "192.0.2.23");
  expect(overridden.status).toBe(429);
  expect((await snapshot(ctx)).events).toEqual([{ kind: "consume", key: "192.0.2.23|/ok", window: "10", max: "100" }]);
  return { results, missing: missing.status, disabled, overridden };
});

compatScenario("rate limit preserves numeric SQL memory and secondary decisions", async ctx => {
  const results = [];
  const cases = [
    ["fractional", "10", "1.5"], ["negative-max", "10", "-1"],
    ["zero-window", "0", "1"], ["negative-window", "-1", "1"],
    ["nan-window", "NaN", "1"], ["infinite-window", "Infinity", "1"],
    ["nan-max", "10", "NaN"], ["infinite-max", "10", "Infinity"],
  ];
  for (const [backendIndex, backend] of ["memory", "database", "secondary"].entries()) {
    for (const [index, [name, window, max]] of cases.entries()) {
      await configure(ctx, { backend, policy: "numeric", window, max });
      const ip = `203.0.113.${10 + backendIndex * 20 + index}`;
      const responses = [];
      for (let step = 0; step < 3; step++) responses.push(await request(ctx, ip));
      let expected = [200, 200, 200];
      if (name === "fractional") expected = backend === "secondary" ? [200, 429, 429] : [200, 200, 429];
      if (name === "negative-max") expected = backend === "secondary" ? [429, 429, 429] : [200, 429, 429];
      if (name === "infinite-window" || (backend === "database" && name === "nan-window")) expected = [200, 429, 429];
      if (name === "nan-max") expected = backend === "secondary" ? [429, 429, 429] : backend === "database" ? [200, 429, 429] : [200, 200, 200];
      expect(responses.map(response => response.status)).toEqual(expected);
      if (name === "infinite-window") expect(responses[1]!.retry).toBe("Infinity");
      if (backend === "database" && name === "nan-window") expect(responses[1]!.retry).toBe("NaN");
      const state = await snapshot(ctx);
      if (backend === "secondary") expect(state.events).toEqual(Array.from({ length: 3 }, () => ({ kind: "increment", key: `${ip}|/ok`, ttl: window })));
      results.push({ backend, name, responses, state });
    }
  }
  return results;
});

compatScenario("rate limit concurrent HTTP requests share one atomic bucket on each backend", async ctx => {
  const results = [];
  for (const [index, backend] of ["memory", "database", "secondary"].entries()) {
    await configure(ctx, { backend, policy: "numeric", window: "60", max: "5" });
    const ip = `198.51.100.${index + 1}`;
    const statuses = await Promise.all(Array.from({ length: 20 }, async () => {
      const response = await fetch(`${ctx.baseURL}/api/limits/ok`, { headers: { "x-forwarded-for": ip } });
      const body = await response.json();
      expect(body).toEqual(response.status === 200 ? { ok: true } : { message: "Too many requests. Please try again later." });
      return response.status;
    }));
    expect(statuses.filter(status => status === 200)).toHaveLength(5);
    expect(statuses.filter(status => status === 429)).toHaveLength(15);
    const state = await snapshot(ctx);
    if (backend === "database") expect(state.rows).toContainEqual({ key: `${ip}|/ok`, count: 5 });
    results.push({ backend, statuses: statuses.sort(), state });
  }
  return results;
});

compatScenario("rate limit process memory survives auth rebuild and shares normalized trailing paths", async ctx => {
  await configure(ctx, { backend: "memory", policy: "numeric", window: "60", max: "1" });
  const first = await request(ctx, "192.0.2.210");
  expect(first.status).toBe(200);
  await ctx.rawRequest({ path: "/__test/rate-limit", method: "POST", json: { restart: true } });
  const rebuilt = await request(ctx, "192.0.2.210", "/api/limits/ok///?different=query");
  expect(rebuilt.status).toBe(429);
  const separate = await request(ctx, "192.0.2.211");
  expect(separate.status).toBe(200);
  return { first, rebuilt, separate };
});
