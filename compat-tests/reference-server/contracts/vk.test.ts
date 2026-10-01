import { expect, test } from "bun:test";
import { vk } from "../node_modules/@better-auth/core/dist/social-providers/vk.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/vk-1.7.6.json", import.meta.url)).json();
const { metadata } = fixture;
type Options = Partial<Parameters<typeof vk>[0]>;
const provider = (options: Options = {}) => vk({ clientId: metadata.clientId, clientSecret: metadata.clientSecret, ...options });
const normalized = (value: unknown) => JSON.parse(JSON.stringify(value));
type RequestRecord = { url: string; method: string; authorization: string | null; contentType: string | null; accept: string | null; body: string };
type HTTPCase = { profile: unknown; profileStatus: number };

async function withHTTP(sample: HTTPCase, run: (requests: RequestRecord[], events: string[]) => Promise<void>) {
  const requests: RequestRecord[] = [];
  const events: string[] = [];
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const url = new URL(request.url);
    const body = await request.text();
    requests.push({ url: `https://id.vk.com${url.pathname}${url.search}`, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), body });
    if (url.pathname === "/oauth2/auth") {
      const name = new URLSearchParams(body).get("grant_type") === "refresh_token" ? "refresh" : "code";
      events.push(name);
      return Response.json(fixture.grants.find((grant: { name: string }) => grant.name === name).rawResponse);
    }
    events.push("profile");
    return Response.json(sample.profile, { status: sample.profileStatus });
  } });
  const original = globalThis.fetch;
  const allowed = new Set([metadata.tokenEndpoint, metadata.profileEndpoint]);
  globalThis.fetch = Object.assign((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (!allowed.has(url.href)) throw new Error(`Unexpected VK URL: ${url.href}`);
    return original(new URL(url.pathname + url.search, server.url), init);
  }, original);
  try { await run(requests, events); } finally { globalThis.fetch = original; await server.stop(true); }
}

test("vk fixture uses pinned Better Auth core 1.7.6", async () => {
  expect((await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version).toBe("1.7.6");
  expect(metadata.version).toBe("1.7.6");
});

for (const sample of fixture.scopeCases) {
  test(`vk ${sample.name} scopes preserve the captured URL and ignore prompt and login hint`, async () => {
    expect((await provider(sample.options).createAuthorizationURL(sample.input)).href).toBe(sample.url);
  });
}

for (const sample of fixture.grants) {
  test(`vk ${sample.name} preserves the captured form request and token response`, async () => {
    await withHTTP(fixture.profileCases[0], async (requests) => {
      const configured = provider();
      const result = sample.name === "code"
        ? await configured.validateAuthorizationCode(sample.input)
        : await configured.refreshAccessToken(sample.input);
      expect(requests).toEqual(sample.requests);
      expect(normalized(result)).toEqual(sample.response);
    });
  });
}

for (const sample of fixture.profileCases) {
  test(`vk profile ${sample.name}`, async () => {
    await withHTTP(sample, async (requests, events) => {
      let mapperCalls = 0;
      let mapperProfile: unknown;
      const patch = { ...sample.mapperPatch };
      for (const key of sample.mapperUndefinedFields) patch[key] = undefined;
      const configured = provider({ mapProfileToUser: async (raw) => {
        mapperCalls++; mapperProfile = normalized(raw); events.push("map:start");
        await Promise.resolve(); events.push("map:end"); return patch;
      } });
      if (sample.clientIdAfterConstruction !== null) configured.options.clientId = sample.clientIdAfterConstruction;
      const result = await configured.getUserInfo({ accessToken: "ordinary-access" });
      events.push("returned");
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(sample.events);
      expect(mapperCalls).toBe(sample.mapperCalls);
      expect(mapperProfile).toEqual(sample.mapperProfile);
      expect(normalized(result)).toEqual(sample.result);
      // JSON omission and JavaScript own undefined remain separate observations.
      expect(result === null ? null : Object.fromEntries(["email", "image", "first_name", "last_name", "birthday", "sex"].map((key) => [key, {
        own: Object.hasOwn(result.user, key), undefined: result.user[key] === undefined,
      }]))).toEqual(sample.presence);
    });
  });
}

test("vk awaits the mapper before checking an omitted raw email", async () => {
  const sample = fixture.profileCases.find((item: { name: string }) => item.name === "mapper supplies omitted email");
  const started = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  await withHTTP(sample, async (requests, events) => {
    const configured = provider({ mapProfileToUser: async (raw) => {
      events.push("map:start"); started.resolve();
      expect(raw).toEqual(sample.mapperProfile);
      await resume.promise;
      events.push("map:end"); return sample.mapperPatch;
    } });
    const pending = configured.getUserInfo({ accessToken: "ordinary-access" }).then((result) => { events.push("returned"); return result; });
    try {
      await started.promise;
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(["profile", "map:start"]);
    } finally { resume.resolve(); }
    expect(normalized(await pending)).toEqual(sample.result);
    expect(events).toEqual(sample.events);
  });
});

for (const sample of fixture.specialCases) {
  test(`vk ${sample.mode} preserves the captured result and callback boundary`, async () => {
    await withHTTP(sample, async (requests, events) => {
      const error = new Error(sample.error?.message ?? `Ordinary VK ${sample.mode}`);
      const custom = fixture.specialCases.find((item: { mode: string }) => item.mode === "custom success").result;
      const options: Options = { mapProfileToUser: async () => { events.push("mapper"); throw error; } };
      if (sample.mode.startsWith("custom")) options.getUserInfo = async () => {
        events.push("custom");
        if (sample.mode === "custom error") throw error;
        return sample.mode === "custom null" ? null : custom;
      };
      const response = provider(options).getUserInfo(sample.input);
      if (sample.error) await expect(response).rejects.toBe(error);
      else {
        const result = await response;
        expect(normalized(result)).toEqual(sample.result);
        expect(result === custom).toBe(sample.sameCustom);
      }
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(sample.events);
    });
  });
}
