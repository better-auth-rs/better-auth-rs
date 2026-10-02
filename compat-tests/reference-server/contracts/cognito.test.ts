import { expect, test } from "bun:test";
import { cognito } from "../node_modules/@better-auth/core/dist/social-providers/cognito.mjs";
import { logger } from "../node_modules/@better-auth/core/dist/env/logger.mjs";
import { generateKeyPair, jwtVerify, SignJWT } from "../node_modules/jose/dist/webapi/index.js";

const fixture = await Bun.file(new URL("../../../tests/fixtures/cognito-1.7.6.json", import.meta.url)).json();
const { metadata } = fixture;
type Options = Partial<Parameters<typeof cognito>[0]>;
const provider = (options: Options = {}) => cognito({
  clientId: metadata.clientIds, clientSecret: metadata.clientSecret,
  domain: metadata.domain, region: metadata.region, userPoolId: metadata.userPoolId, ...options,
});
const normalized = (value: unknown) => JSON.parse(JSON.stringify(value));
const presence = (result: any) => result === null ? null : Object.fromEntries(["name", "email", "image", "emailVerified"].map((key) => [key, {
  own: Object.hasOwn(result.user, key), undefined: result.user[key] === undefined,
}]));
const { privateKey, publicKey } = await generateKeyPair("RS256");
const runIssuedAt = Math.floor(Date.now() / 1000);

// Refresh only JWT timestamps so the local signed fixture remains valid on later runs.
function freshSample(template: any, issuedAt = runIssuedAt): any {
  if (Array.isArray(template)) return template.map((value) => freshSample(value, issuedAt));
  if (template === null || typeof template !== "object") return template;
  const sample = Object.fromEntries(Object.entries(template).map(([key, value]) => [key, freshSample(value, issuedAt)]));
  if (sample.iss === metadata.issuer && Object.hasOwn(sample, "iat")) {
    sample.iat = issuedAt; sample.exp = issuedAt + 3600;
  }
  return sample;
}
async function requestInput(sample: any) {
  if (!sample.input.idToken) return sample.input;
  const claims = sample.source === "id-token" ? sample.profile
    : freshSample(fixture.profileCases.find((entry: { name: string }) => entry.name === "signed default").profile);
  const idToken = await new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "ordinary-local-cognito" }).sign(privateKey);
  await jwtVerify(idToken, publicKey, { issuer: metadata.issuer, audience: metadata.clientIds, maxTokenAge: "1h" });
  return { ...sample.input, idToken };
}

type RequestRecord = { url: string; method: string; authorization: string | null; contentType: string | null; accept: string | null; body: string };
async function withHTTP(sample: any, run: (requests: RequestRecord[], events: string[], logs: unknown[]) => Promise<void>, ordinaryError?: Error) {
  const requests: RequestRecord[] = [], events: string[] = [], logs: unknown[] = [];
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const url = new URL(request.url), body = await request.text();
    requests.push({ url: `https://${metadata.domain}${url.pathname}${url.search}`, method: request.method, authorization: request.headers.get("authorization"), contentType: request.headers.get("content-type"), accept: request.headers.get("accept"), body });
    if (url.pathname === "/oauth2/token") {
      const grant = new URLSearchParams(body).get("grant_type") === "refresh_token" ? "refresh" : "code";
      events.push(grant);
      return Response.json(fixture.grants.find((entry: { name: string }) => entry.name === grant).rawResponse);
    }
    events.push("profile"); return Response.json(sample.profile, { status: sample.profileStatus });
  } });
  const originalFetch = globalThis.fetch, originalError = logger.error;
  const allowed = new Set([metadata.tokenEndpoint, metadata.profileEndpoint]);
  globalThis.fetch = Object.assign((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (!allowed.has(url.href)) throw new Error(`Unexpected Cognito URL: ${url.href}`);
    return originalFetch(new URL(url.pathname + url.search, server.url), init);
  }, originalFetch);
  logger.error = (message: unknown, error: unknown) => {
    events.push("log:error");
    logs.push({ message, error: error instanceof Error ? { name: error.name, message: error.message, sameError: error === ordinaryError } : error });
  };
  try { await run(requests, events, logs); }
  finally { globalThis.fetch = originalFetch; logger.error = originalError; await server.stop(true); }
}

test("cognito contract uses pinned Better Auth core 1.7.6", async () => {
  expect((await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version).toBe("1.7.6");
  expect(metadata.version).toBe("1.7.6");
});
for (const sample of fixture.scopeCases) {
  test(`cognito ${sample.name} preserves the captured authorization URL`, async () => {
    expect((await provider(sample.options).createAuthorizationURL(sample.input)).href).toBe(sample.url);
  });
}
for (const sample of fixture.grants) {
  test(`cognito ${sample.name} preserves the captured POST request and token result`, async () => {
    await withHTTP(fixture.profileCases[0], async (requests, events, logs) => {
      const configured = provider();
      const result = sample.name === "code" ? await configured.validateAuthorizationCode(sample.input)
        : await configured.refreshAccessToken(sample.input);
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(sample.events);
      expect(logs).toEqual([]);
      expect(normalized(result)).toEqual(sample.response);
    });
  });
}
for (const template of fixture.profileCases) {
  test(`cognito profile ${template.name}`, async () => {
    const sample = freshSample(template);
    await withHTTP(sample, async (requests, events, logs) => {
      let mapperCalls = 0, mapperProfile: unknown;
      const patch = sample.mapperEmailMode === "undefined" ? { ...sample.mapperPatch, email: undefined } : sample.mapperPatch;
      const configured = provider({ mapProfileToUser: async (raw) => {
        mapperCalls++; mapperProfile = normalized(raw); events.push("map:start");
        await Promise.resolve(); events.push("map:end"); return patch;
      } });
      const result = await configured.getUserInfo(await requestInput(sample)); events.push("returned");
      expect(requests).toEqual(sample.requests);
      expect(events).toEqual(sample.events);
      expect(logs).toEqual(sample.logs);
      expect(mapperCalls).toBe(sample.mapperCalls);
      expect(mapperProfile).toEqual(sample.mapperProfile);
      expect(normalized(result)).toEqual(sample.result);
      // JSON omission and JavaScript own undefined are separate contract observations.
      expect(presence(result)).toEqual(sample.presence);
    });
  });
}
test("cognito awaits HTTP and signed-profile mappers with the captured raw inputs", async () => {
  for (const name of ["http mapper fills email", "signed given name enrichment"]) {
    const sample = freshSample(fixture.profileCases.find((entry: { name: string }) => entry.name === name));
    const started = Promise.withResolvers<void>(), resume = Promise.withResolvers<void>();
    await withHTTP(sample, async (requests, events) => {
      const configured = provider({ mapProfileToUser: async (raw) => {
        events.push("map:start"); started.resolve();
        try { expect(raw).toEqual(sample.mapperProfile); await resume.promise; }
        finally { events.push("map:end"); }
        return sample.mapperPatch;
      } });
      const pending = configured.getUserInfo(await requestInput(sample)).then((value) => { events.push("returned"); return value; });
      try {
        await started.promise;
        expect(requests).toEqual(sample.requests);
        expect(events).toEqual(sample.source === "http" ? ["profile", "map:start"] : ["map:start"]);
      } finally { resume.resolve(); }
      expect(normalized(await pending)).toEqual(sample.result);
      expect(events).toEqual(sample.events);
    });
  }
});
for (const template of fixture.specialCases) {
  test(`cognito ${template.mode} preserves the captured result, logs, and callback boundary`, async () => {
    const sample = freshSample(template), error = new Error(`Ordinary Cognito ${sample.mode}`);
    await withHTTP(sample, async (requests, events, logs) => {
      let mapperCalls = 0; const mapperProfiles: unknown[] = [];
      const custom = fixture.specialCases.find((entry: { mode: string }) => entry.mode === "custom success").result;
      const options: Options = { mapProfileToUser: async (raw) => {
        mapperCalls++; mapperProfiles.push(normalized(raw)); events.push("mapper");
        if (sample.mode === "signed mapper fallback" && mapperCalls === 2) return { name: "Fallback Cognito Owner" };
        throw error;
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
      expect(logs).toEqual(sample.logs);
      expect(mapperCalls).toBe(sample.mapperCalls);
      expect(mapperProfiles).toEqual(sample.mapperProfiles);
    }, error);
  });
}
