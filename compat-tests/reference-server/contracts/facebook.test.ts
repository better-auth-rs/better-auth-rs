import { expect, test } from "bun:test";
import { facebook } from "../node_modules/@better-auth/core/dist/social-providers/facebook.mjs";
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "../node_modules/jose/dist/webapi/index.js";

const fixture = await Bun.file(new URL("../../../tests/fixtures/facebook-1.7.6.json", import.meta.url)).json();
const { metadata } = fixture;
type Options = Partial<Parameters<typeof facebook>[0]>;
const provider = (options: Options = {}) => facebook({ clientId: metadata.clientIds, clientSecret: metadata.clientSecret, ...options });
const normalized = (value: unknown) => JSON.parse(JSON.stringify(value));
const presence = (result: any) => result === null ? null : Object.fromEntries(["name", "email", "image", "emailVerified"].map(key => [key, {
  own: Object.hasOwn(result.user, key), undefined: result.user[key] === undefined,
}]));
const { privateKey, publicKey } = await generateKeyPair("RS256");
const publicJwk = { ...(await exportJWK(publicKey)), kid: "ordinary-local-facebook", alg: "RS256", use: "sig" };
const runIssuedAt = Math.floor(Date.now() / 1000);

// Refresh only JWT timestamps so the locally verified fixture remains valid on later runs.
function freshSample(template: any): any {
  if (Array.isArray(template)) return template.map(freshSample);
  if (template === null || typeof template !== "object") return template;
  const sample = Object.fromEntries(Object.entries(template).map(([key, value]) => [key, freshSample(value)]));
  if (sample.iss === metadata.issuer && Object.hasOwn(sample, "iat")) {
    sample.iat = runIssuedAt; sample.exp = runIssuedAt + 3600;
  }
  return sample;
}
async function requestInput(sample: any) {
  if (!sample.input.idToken) return sample.input;
  const idToken = await new SignJWT(sample.profile).setProtectedHeader({ alg: "RS256", kid: publicJwk.kid }).sign(privateKey);
  const verified = await jwtVerify(idToken, publicKey, { issuer: metadata.issuer, audience: metadata.clientIds, algorithms: ["RS256"] });
  if (verified.payload.nonce !== metadata.nonce) throw new Error("Local fixture nonce differs from its declared nonce");
  return { ...sample.input, idToken };
}

type RequestRecord = { url: string; method: string; authorization: string | null; contentType: string | null; accept: string | null; body: string };
async function withHTTP(sample: any, run: (requests: RequestRecord[], events: string[]) => Promise<void>) {
  const requests: RequestRecord[] = [], events: string[] = [];
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const url = new URL(request.url), body = await request.text();
    const origin = url.pathname.includes("openid/jwks") ? "https://limited.facebook.com" : "https://graph.facebook.com";
    requests.push({ url: origin + url.pathname + url.search, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), body });
    if (url.pathname === "/.well-known/oauth/openid/jwks/") { events.push("keys"); return Response.json({ keys: [publicJwk] }); }
    if (url.pathname === "/debug_token") { events.push("debug"); return Response.json(sample.debugResponse, { status: sample.debugStatus }); }
    if (url.pathname === "/me") { events.push("profile"); return Response.json(sample.profile, { status: sample.profileStatus }); }
    const grant = new URLSearchParams(body).get("grant_type") === "refresh_token" ? "refresh" : "code";
    events.push(grant);
    return Response.json(fixture.grants.find((entry: { name: string }) => entry.name === grant).rawResponse);
  } });
  const originalFetch = globalThis.fetch;
  const allowed = new Set([metadata.tokenEndpoint, metadata.jwksEndpoint,
    ...fixture.profileCases.flatMap((entry: { requests: RequestRecord[] }) => entry.requests.map(request => request.url)),
  ]);
  globalThis.fetch = Object.assign((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (!allowed.has(url.href)) throw new Error(`Unexpected Facebook URL: ${url.href}`);
    return originalFetch(new URL(url.pathname + url.search, server.url), init);
  }, originalFetch);
  try { await run(requests, events); }
  finally { globalThis.fetch = originalFetch; await server.stop(true); }
}

test("facebook contract uses pinned Better Auth core 1.7.6", async () => {
  expect((await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version).toBe("1.7.6");
  expect(metadata.version).toBe("1.7.6");
});
test("facebook preserves the captured Limited Login verification declaration", () => {
  const declaration = provider().idToken;
  expect({ issuer: declaration.issuer, audience: declaration.audience, algorithms: declaration.algorithms }).toEqual(fixture.idTokenDeclaration);
});
for (const sample of fixture.scopeCases) {
  test(`facebook ${sample.name} preserves the captured authorization URL`, async () => {
    expect((await provider(sample.options).createAuthorizationURL(sample.input)).href).toBe(sample.url);
  });
}
for (const sample of fixture.grants) {
  test(`facebook ${sample.name} preserves the captured POST request and token result`, async () => {
    await withHTTP(fixture.profileCases[0], async (requests, events) => {
      const configured = provider();
      const result = sample.name === "code" ? await configured.validateAuthorizationCode(sample.input)
        : await configured.refreshAccessToken(sample.input);
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(sample.events);
      expect(normalized(result)).toEqual(sample.response);
    });
  });
}
for (const template of fixture.profileCases) {
  test(`facebook ${template.source} profile ${template.name}`, async () => {
    const sample = freshSample(template);
    await withHTTP(sample, async (requests, events) => {
      let mapperCalls = 0, mapperProfile: unknown;
      const patch = sample.mapperEmailMode === "undefined" ? { ...sample.mapperPatch, email: undefined } : sample.mapperPatch;
      const configured = provider({ ...sample.options, mapProfileToUser: async (raw) => {
        mapperCalls++; mapperProfile = normalized(raw); events.push("map:start");
        await Promise.resolve(); events.push("map:end"); return patch;
      } });
      const result = await configured.getUserInfo(await requestInput(sample)); events.push("returned");
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(sample.events);
      expect(mapperCalls).toBe(sample.mapperCalls);
      expect(mapperProfile).toEqual(sample.mapperProfile);
      expect(normalized(result)).toEqual(sample.result);
      // JSON omission and JavaScript own undefined remain separate observations.
      expect(presence(result)).toEqual(sample.presence);
    });
  });
}
test("facebook awaits Graph and Limited Login mappers before applying captured overrides", async () => {
  for (const source of ["graph", "limited"]) {
    const sample = freshSample(fixture.profileCases.find((entry: { source: string; name: string }) => entry.source === source && entry.name === "mapped display"));
    const started = Promise.withResolvers<void>(), resume = Promise.withResolvers<void>();
    await withHTTP(sample, async (requests, events) => {
      const configured = provider({ mapProfileToUser: async (raw) => {
        events.push("map:start"); started.resolve();
        try { expect(raw).toEqual(sample.mapperProfile); await resume.promise; }
        finally { events.push("map:end"); }
        return sample.mapperPatch;
      } });
      const pending = configured.getUserInfo(await requestInput(sample)).then(result => { events.push("returned"); return result; });
      try {
        await started.promise;
        expect(requests).toEqual(sample.requests);
        expect(events).toEqual(source === "graph" ? ["debug", "profile", "map:start"] : ["map:start"]);
      } finally { resume.resolve(); }
      expect(normalized(await pending)).toEqual(sample.result);
      expect(events).toEqual(sample.events);
    });
  }
});
for (const template of fixture.specialCases) {
  test(`facebook ${template.mode} preserves the captured result and callback boundary`, async () => {
    const sample = freshSample(template), error = new Error(`Ordinary Facebook ${sample.mode}`);
    await withHTTP(sample, async (requests, events) => {
      let mapperCalls = 0; const mapperProfiles: unknown[] = [];
      const custom = fixture.specialCases.find((entry: { mode: string }) => entry.mode === "custom success").result;
      const options: Options = { mapProfileToUser: async (raw) => {
        mapperCalls++; mapperProfiles.push(normalized(raw)); events.push("mapper"); throw error;
      } };
      if (sample.mode.startsWith("custom")) options.getUserInfo = async () => {
        events.push("custom"); if (sample.mode === "custom error") throw error;
        return sample.mode === "custom null" ? null : custom;
      };
      const pending = provider(options).getUserInfo(await requestInput(sample));
      if (sample.error) {
        await expect(pending).rejects.toBe(error); events.push("rejected");
        expect({ name: error.name, message: error.message, sameError: true }).toEqual(sample.error);
      } else {
        const result = await pending; events.push("returned");
        expect(normalized(result)).toEqual(sample.result);
        expect(result === custom).toBe(sample.sameCustom);
      }
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(sample.events);
      expect(mapperCalls).toBe(sample.mapperCalls);
      expect(mapperProfiles).toEqual(sample.mapperProfiles);
    });
  });
}
