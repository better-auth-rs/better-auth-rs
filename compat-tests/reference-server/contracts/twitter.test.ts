import { expect, test } from "bun:test";
import { twitter } from "../node_modules/@better-auth/core/dist/social-providers/twitter.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/twitter-1.7.6.json", import.meta.url)).json();
const { metadata } = fixture;
type Options = Partial<Parameters<typeof twitter>[0]>;
const provider = (options: Options = {}) => twitter({ clientId: metadata.clientId, clientSecret: metadata.clientSecret, ...options });
const normalized = (value: unknown) => JSON.parse(JSON.stringify(value));
type RequestRecord = { url: string; method: string; authorization: string | null; contentType: string | null; accept: string | null; body: string };
type HTTPCase = { profile: unknown; emailResponse: unknown; profileStatus: number; emailStatus: number };

async function withHTTP(sample: HTTPCase, run: (requests: RequestRecord[], events: string[]) => Promise<void>) {
  const requests: RequestRecord[] = [];
  const events: string[] = [];
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const url = new URL(request.url);
    const body = await request.text();
    requests.push({ url: `https://api.x.com${url.pathname}${url.search}`, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), body });
    if (url.pathname === "/2/oauth2/token") {
      const name = new URLSearchParams(body).get("grant_type") === "refresh_token" ? "refresh" : "code";
      events.push(name);
      return Response.json(fixture.grants.find((grant: { name: string }) => grant.name === name).rawResponse);
    }
    const first = url.searchParams.get("user.fields") === "profile_image_url";
    events.push(first ? "profile" : "confirmed_email");
    return Response.json(first ? sample.profile : sample.emailResponse, { status: first ? sample.profileStatus : sample.emailStatus });
  } });
  const original = globalThis.fetch;
  const allowed = new Set([metadata.tokenEndpoint, metadata.profileEndpoint, metadata.emailEndpoint]);
  globalThis.fetch = Object.assign((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (!allowed.has(url.href)) throw new Error(`Unexpected Twitter URL: ${url.href}`);
    return original(new URL(url.pathname + url.search, server.url), init);
  }, original);
  try { await run(requests, events); } finally { globalThis.fetch = original; await server.stop(true); }
}

test("twitter fixture uses pinned Better Auth core 1.7.6", async () => {
  expect((await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version).toBe("1.7.6");
  expect(metadata.version).toBe("1.7.6");
});

for (const sample of fixture.scopeCases) {
  test(`twitter ${sample.name} scopes preserve the captured URL and ignore prompt and login hint`, async () => {
    const url = await provider(sample.options).createAuthorizationURL(sample.input);
    expect(url.href).toBe(sample.url);
  });
}

for (const sample of fixture.grants) {
  test(`twitter ${sample.name} uses the captured Basic request and token response`, async () => {
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
  test(`twitter profile ${sample.name}`, async () => {
    await withHTTP(sample, async (requests, events) => {
      let mapperCalls = 0;
      let mapperProfile: unknown;
      const configured = provider({ mapProfileToUser: async (raw) => {
        mapperCalls++; mapperProfile = normalized(raw); events.push("map:start");
        await Promise.resolve(); events.push("map:end");
        return sample.mapperEmailMode === "undefined" ? { ...sample.mapperPatch, email: undefined } : sample.mapperPatch;
      } });
      const result = await configured.getUserInfo({ accessToken: "ordinary-access" });
      events.push("returned");
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(sample.events);
      expect(mapperCalls).toBe(sample.mapperCalls);
      expect(mapperProfile).toEqual(sample.mapperProfile);
      expect(normalized(result)).toEqual(sample.result);
      // JSON omits undefined; these diagnostics preserve the separate JavaScript own-property result.
      expect(result === null ? null : {
        userEmailOwn: Object.hasOwn(result.user, "email"), userEmailUndefined: result.user.email === undefined,
        userImageOwn: Object.hasOwn(result.user, "image"), userImageUndefined: result.user.image === undefined,
        dataEmailOwn: Object.hasOwn(result.data.data, "email"), dataEmailUndefined: result.data.data.email === undefined,
      }).toEqual(sample.presence);
    });
  });
}

test("twitter awaits the mapper after both HTTP reads before returning the mapped result", async () => {
  const sample = fixture.profileCases[0];
  const started = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  await withHTTP(sample, async (requests, events) => {
    const configured = provider({ mapProfileToUser: async (raw) => {
      events.push("map:start"); started.resolve();
      expect(raw).toEqual(sample.mapperProfile);
      await resume.promise;
      events.push("map:end"); return {};
    } });
    const pending = configured.getUserInfo({ accessToken: "ordinary-access" }).then((result) => { events.push("returned"); return result; });
    try {
      await started.promise;
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(["profile", "confirmed_email", "map:start"]);
    } finally { resume.resolve(); }
    expect(normalized(await pending)).toEqual(sample.result);
    expect(events).toEqual(sample.events);
  });
});

for (const sample of fixture.specialCases) {
  test(`twitter ${sample.mode} preserves the captured result and callback boundary`, async () => {
    await withHTTP(fixture.profileCases[0], async (requests, events) => {
      const error = new Error(sample.error?.message ?? `Ordinary Twitter ${sample.mode}`);
      const custom = fixture.specialCases.find((item: { mode: string }) => item.mode === "custom success").result;
      const options: Options = { mapProfileToUser: async () => { events.push("mapper"); throw error; } };
      if (sample.mode !== "mapper error") options.getUserInfo = async () => {
        events.push("custom");
        if (sample.mode === "custom error") throw error;
        return sample.mode === "custom null" ? null : custom;
      };
      const response = provider(options).getUserInfo({ accessToken: "ordinary-access" });
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
