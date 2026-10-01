import { expect } from "bun:test";

type Invoke = (input: any) => Promise<any>;
const stages = (events: any[]) => events.map(event => event.stage);
const body = (call: any) => { expect(call.output).toMatchObject({ thrown: false, status: 200 }); return call.output.body; };
const dynamic = { allowedHosts: ["*.tenant.test", "localhost:4000", "[::1]:4000"], protocol: "auto" };
const url = (host: string) => `https://${host}/api/auth/context-probe`;

export const dynamicContextScenarios: { name: string; run: (invoke: Invoke) => Promise<unknown> }[] = [
  {
    name: "Static native calls preserve initialized trust while HTTP resolves trust before request hooks",
    async run(invoke) {
      const result = await invoke({ baseURL: "https://fixed.test/custom", basePath: "/ignored", calls: [
        { id: "native", transport: "native", headers: { "x-tenant": "a" } },
        { id: "native-request", transport: "native", nativeRequest: true, url: "https://other.test/custom/context-probe", requestHeaders: { "x-tenant": "b" } },
        { id: "http", transport: "http", url: "https://fixed.test/custom/context-probe", requestHeaders: { "x-tenant": "c" } },
      ] });
      expect(stages(result.initEvents)).toEqual(["origins", "providers"]);
      expect(result.initEvents.every((event: any) => event.request === null)).toBe(true);
      for (const call of result.calls.slice(0, 2)) {
        expect(body(call).before).toMatchObject({ baseURL: "https://fixed.test/custom", optionURL: "https://fixed.test", providers: ["initial-provider"] });
        expect(stages(call.events)).toEqual(["before", "endpoint", "after"]);
      }
      expect(body(result.calls[0]).request).toBeNull();
      expect(body(result.calls[1]).request.tenant).toBe("b");
      expect(body(result.calls[2]).before.providers).toEqual(["c-provider"]);
      expect(stages(result.calls[2].events)).toEqual(["origins", "providers", "onRequest", "before", "endpoint", "after"]);
      expect(result.final).toEqual(result.initialized);
      return result;
    },
  },
  {
    name: "Dynamic native source priority preserves synthetic trust requests without manufacturing an endpoint Request",
    async run(invoke) {
      const result = await invoke({ baseURL: dynamic, calls: [
        { id: "headers", transport: "native", headers: { host: "a.tenant.test", "x-tenant": "a" } },
        { id: "request", transport: "native", nativeRequest: true, url: "http://b.tenant.test/unrelated/context-probe", requestHeaders: { "x-tenant": "b" }, headers: { host: "a.tenant.test", "x-tenant": "a" } },
        { id: "empty", transport: "native", headers: {} },
        { id: "omitted", transport: "native" },
        { id: "no-host", transport: "native", headers: { "x-tenant": "a" } },
      ] });
      const first = body(result.calls[0]);
      expect(first.before).toMatchObject({ baseURL: "https://a.tenant.test/api/auth", optionURL: "https://a.tenant.test", providers: ["a-provider"] });
      expect(first.request).toBeNull();
      expect(result.calls[0].events[0].request).toMatchObject({ url: "https://a.tenant.test/api/auth", method: "GET", host: "a.tenant.test", tenant: "a" });
      const second = body(result.calls[1]);
      expect(second.before).toMatchObject({ baseURL: "http://b.tenant.test/api/auth", providers: ["b-provider"] });
      expect(second.headersTenant).toBe("a");
      expect(result.calls[1].events[0].request.url).toBe("http://b.tenant.test/unrelated/context-probe");
      for (const call of result.calls.slice(2)) {
        expect(call.output).toMatchObject({ thrown: true, kind: "APIError", status: 500 });
        expect(call.output.body.message).toBe("Dynamic baseURL could not be resolved for this direct auth.api call. Pass `headers: request.headers` (or `request`) to the call, or add `fallback` to your baseURL config.");
        expect(call.events).toEqual([]);
      }
      expect(result.final).toEqual(result.initialized);
      return result;
    },
  },
  {
    name: "Trust callbacks run before HTTP parsing and rerun origin policy only at CSRF boundaries",
    async run(invoke) {
      const calls = [
        { id: "csrf", transport: "http", method: "POST", url: url("a.tenant.test"), requestHeaders: { origin: "https://a.tenant.test", cookie: "fixture=1", "x-tenant": "a" } },
        { id: "malformed", transport: "http", method: "POST", url: url("a.tenant.test"), rawBody: "{" },
        ...["origins", "providers"].flatMap(stage => ["api", "ordinary"].flatMap(kind => ["http", "native"].map(transport => ({ id: `${stage}-${kind}-${transport}`, transport, nativeRequest: transport === "native", url: url("a.tenant.test"), requestHeaders: { "x-fail-trust": `${stage}-${kind}` } })))),
      ];
      const result = await invoke({ baseURL: dynamic, calls });
      expect(stages(result.calls[0].events)).toEqual(["origins", "providers", "onRequest", "origins", "before", "endpoint", "after"]);
      body(result.calls[0]);
      expect(result.calls[1].output).toMatchObject({ thrown: false, status: 400 });
      expect(stages(result.calls[1].events)).toEqual(["origins", "providers", "onRequest"]);
      for (const call of result.calls.slice(2)) {
        const [stage, kind] = call.id.split("-");
        expect(stages(call.events)).toEqual(stage === "origins" ? ["origins"] : ["origins", "providers"]);
        expect(call.output).toEqual(kind === "api"
          ? { thrown: true, kind: "APIError", status: 400, body: { code: "TRUST_CALLBACK_REJECTED", message: `${stage} rejected` } }
          : { thrown: true, kind: "Error", message: `${stage} failed` });
      }
      return result;
    },
  },
  {
    name: "Fallback and host failures retain distinct HTTP and native error boundaries",
    async run(invoke) {
      const outputs = [];
      for (const fallback of [undefined, "https://fallback.test/custom"]) {
        const result = await invoke({ baseURL: { allowedHosts: ["*.tenant.test"], ...(fallback ? { fallback } : {}) }, calls: [
          { id: "evil-http", transport: "http", url: "https://evil.test/custom/context-probe" },
          { id: "evil-native", transport: "native", headers: { host: "evil.test" } },
          { id: "invalid-native", transport: "native", headers: { host: "bad host" } },
          { id: "source-free", transport: "native", headers: { "x-tenant": "a" } },
        ] });
        for (const call of result.calls) {
          if (fallback) {
            expect(body(call).before).toMatchObject({ baseURL: fallback, optionURL: "https://fallback.test" });
          } else {
            expect(call.output).toMatchObject(call.id === "evil-http" ? { thrown: true, kind: "BetterAuthError" } : { thrown: true, kind: "APIError", status: 500 });
            expect(call.events).toEqual([]);
          }
        }
        if (fallback) {
          expect(body(result.calls[0]).before.providers).toEqual(["initial-provider"]);
          expect(result.calls[3].events.slice(0, 2).every((event: any) => event.request === null)).toBe(true);
        }
        outputs.push(result);
      }
      const empty = await invoke({ baseURL: { allowedHosts: [] }, calls: [] });
      expect(empty.initializationError).toMatchObject({ thrown: true, kind: "BetterAuthError", message: "baseURL.allowedHosts cannot be empty. Provide at least one allowed host pattern (e.g., [\"myapp.com\", \"*.vercel.app\"])." });
      outputs.push(empty);
      return outputs;
    },
  },
  {
    name: "Proxy opt-in and protocol omission differ from explicit auto trust expansion",
    async run(invoke) {
      const outputs = [];
      for (const proxy of [false, true]) {
        const result = await invoke({ baseURL: dynamic, proxy, calls: [
          { id: "forwarded", transport: "http", url: url("a.tenant.test"), requestHeaders: { host: "a.tenant.test", "x-forwarded-host": "b.tenant.test", "x-forwarded-proto": "http" } },
          { id: "invalid-forwarded", transport: "http", url: url("a.tenant.test"), requestHeaders: { host: "b.tenant.test", "x-forwarded-host": "evil.test/path", "x-forwarded-proto": "invalid" } },
          { id: "loopback", transport: "native", headers: { host: "localhost:4000" } },
          { id: "ipv6", transport: "native", headers: { host: "[::1]:4000" } },
        ] });
        expect(body(result.calls[0]).before.baseURL).toBe(proxy ? "http://b.tenant.test/api/auth" : "https://a.tenant.test/api/auth");
        expect(body(result.calls[1]).before.baseURL).toBe("https://b.tenant.test/api/auth");
        expect(body(result.calls[2]).before.baseURL).toBe("http://localhost:4000/api/auth");
        expect(body(result.calls[3]).before.baseURL).toBe("http://[::1]:4000/api/auth");
        outputs.push(result);
      }
      for (const protocol of [undefined, "auto", "http", "https"]) {
        const result = await invoke({ baseURL: { allowedHosts: ["a.tenant.test"], ...(protocol ? { protocol } : {}) }, proxy: true, calls: [
          { id: "protocol", transport: "native", headers: { host: "a.tenant.test", "x-forwarded-proto": "http" } },
        ] });
        const context = body(result.calls[0]).before;
        expect(context.cookie).toEqual(result.initialized.cookie);
        expect(context.baseURL).toBe(`${protocol === "https" ? "https" : "http"}://a.tenant.test/api/auth`);
        expect(context.origins.filter((origin: string) => origin.includes("a.tenant.test"))).toEqual(protocol === "auto" ? ["https://a.tenant.test", "http://a.tenant.test"] : [protocol === "http" ? "http://a.tenant.test" : "https://a.tenant.test"]);
        outputs.push(result);
      }
      return outputs;
    },
  },
  {
    name: "Concurrent tenant requests isolate resolved context and cookie domains across awaits",
    async run(invoke) {
      const result = await invoke({ baseURL: dynamic, crossSubdomain: true, parallel: true, calls: [
        { id: "a", transport: "http", url: url("a.tenant.test"), requestHeaders: { "x-tenant": "a" } },
        { id: "b", transport: "http", url: url("b.tenant.test"), requestHeaders: { "x-tenant": "b" } },
      ] });
      for (const call of result.calls) {
        const observed = body(call);
        expect(observed.before).toEqual(observed.after);
        expect(observed.after).toMatchObject({ baseURL: `https://${call.id}.tenant.test/api/auth`, optionURL: `https://${call.id}.tenant.test`, providers: [`${call.id}-provider`], cookie: { name: "__Secure-better-auth.session_token", secure: true, domain: `${call.id}.tenant.test` } });
        expect(observed.after.origins).toContain(`https://${call.id}.frontend.test`);
        expect(observed.after.origins).not.toContain(`https://${call.id === "a" ? "b" : "a"}.frontend.test`);
        expect(stages(call.events)).toEqual(["origins", "providers", "onRequest", "before", "endpoint", "after"]);
        expect(call.events.every((event: any) => event.baseURL === undefined || event.baseURL === observed.after.baseURL)).toBe(true);
      }
      expect(result.final).toEqual(result.initialized);
      expect(result.initialized.baseURL).toBe("");
      return result;
    },
  },
  {
    name: "Plugin origins preserve initialization timing and static-first aggregation",
    async run(invoke) {
      const result = await invoke({ baseURL: "https://fixed.test", pluginOrigins: [
        { id: "static-origin", dynamic: false, values: ["https://static.plugin.test"] },
        { id: "dynamic-origin", dynamic: true, values: ["https://dynamic.plugin.test"] },
      ], calls: [
        { id: "native", transport: "native" },
        { id: "http", transport: "http", url: "https://fixed.test/api/auth/context-probe", requestHeaders: { "x-tenant": "a" } },
      ] });
      expect(stages(result.initEvents)).toEqual(["origins", "providers", "init:static-origin", "init:dynamic-origin"]);
      expect(body(result.calls[0]).before.origins).toEqual(["https://fixed.test", "https://initial.frontend.test"]);
      expect(body(result.calls[1]).before.origins).toEqual(["https://fixed.test", "https://static.plugin.test", "https://a.frontend.test", "https://dynamic.plugin.test"]);
      expect(stages(result.calls[1].events)).toEqual(["origins", "origins:dynamic-origin", "providers", "onRequest", "before", "endpoint", "after"]);
      return result;
    },
  },
];
