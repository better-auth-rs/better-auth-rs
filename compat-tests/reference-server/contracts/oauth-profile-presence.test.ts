import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import fixture from "../../../tests/fixtures/social-http-providers-1.7.6.json";

const baseURL = "http://oauth-profile-presence.example.test";
const tokens = { accessToken: "ordinary-profile-presence-token" };
const mappedEmail = "mapped@example.test";
const profiles = {
  huggingface: fixture.providers.huggingface,
  vercel: fixture.providers.vercel,
  discord: {
    userinfoEndpoint: "https://discord.com/api/users/%40me",
    profile: { id: "123456789", email: "owner@example.test", username: "Owner", avatar: "portrait", verified: true },
    defaultUser: { name: "Owner", email: "owner@example.test", image: "https://cdn.discordapp.com/avatars/123456789/portrait.png", emailVerified: true },
  },
};
type HttpProvider = keyof typeof profiles;
type EmailPatch = { email?: string | null | undefined };

function createAuth(id: string, options: Record<string, unknown>, database = {
  user: [], account: [], session: [], verification: [],
} as Record<string, Record<string, unknown>[]>) {
  return betterAuth({
    secret: "oauth-profile-presence-contract-secret-at-least-32-characters",
    baseURL,
    database: memoryAdapter(database),
    logger: { disabled: true },
    telemetry: { enabled: false },
    socialProviders: { [id]: { clientId: fixture.clientId, clientSecret: fixture.clientSecret, ...options } },
  });
}

const cookieHeader = (response: Response) => response.headers.getSetCookie()
  .map((value) => value.split(";", 1)[0]).join("; ");

function setup(id: HttpProvider, options: Record<string, unknown> = {}) {
  const database: Record<string, Record<string, unknown>[]> = {
    user: [], account: [], session: [], verification: [],
  };
  const events: string[] = [];
  let profile: Record<string, unknown> = { ...profiles[id].profile };
  let patch: EmailPatch = {};
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      if (new URL(request.url).pathname === "/token") {
        events.push("token");
        return Response.json({ access_token: tokens.accessToken, token_type: "Bearer", expires_in: 3600 });
      }
      events.push("profile");
      expect(request.method).toBe("GET");
      expect(request.headers.get("authorization")).toBe(`Bearer ${tokens.accessToken}`);
      return Response.json(profile);
    },
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = Object.assign((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    const path = url === profiles[id].userinfoEndpoint ? "/profile"
      : url === fixture.providers.huggingface.tokenEndpoint ? "/token" : undefined;
    if (!path) throw new Error(`Unexpected profile contract URL: ${url}`);
    return originalFetch(new URL(path, server.url), init);
  }, originalFetch);
  const auth = createAuth(id, {
    mapProfileToUser: async (raw: Record<string, unknown>) => {
      events.push("map");
      expect(raw).toEqual(profile);
      return patch;
    },
    ...options,
  }, database);
  return {
    auth, database, events,
    setProfile(value: Record<string, unknown>) { profile = value; },
    setPatch(value: EmailPatch) { patch = value; },
    async login() {
      const start = await auth.handler(new Request(`${baseURL}/api/auth/sign-in/social`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: baseURL },
        body: JSON.stringify({ provider: id, callbackURL: `${baseURL}/welcome`, disableRedirect: true }),
      }));
      expect(start.status).toBe(200);
      const state = new URL((await start.json()).url).searchParams.get("state");
      expect(state).toBeTruthy();
      const query = new URLSearchParams({ code: "ordinary-code", state: state! });
      const response = await auth.handler(new Request(`${baseURL}/api/auth/callback/${id}?${query}`, {
        headers: { cookie: cookieHeader(start) },
      }));
      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toBe(`${baseURL}/welcome`);
      for (const model of ["user", "account", "session"]) expect(database[model]).toHaveLength(1);
      expect(events).toEqual(["token", "profile", "map"]);
      return cookieHeader(response);
    },
    async close() { globalThis.fetch = originalFetch; await server.stop(true); },
  };
}

test("uses pinned Better Auth core 1.7.6", async () => {
  const core = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
  expect(core.version).toBe("1.7.6");
});

for (const id of ["google", "github", "discord", "gitlab", "spotify", "huggingface", "polar", "vercel", "figma", "dropbox", "kick", "cloudflare"]) {
  test(`${id} custom getUserInfo returns successful null without HTTP or mapper calls`, async () => {
    const events: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = Object.assign(async () => {
      events.push("http");
      throw new Error("Custom getUserInfo must skip HTTP");
    }, originalFetch);
    try {
      const auth = createAuth(id, {
        getUserInfo: async (received: unknown) => {
          events.push("custom");
          expect(received).toEqual(tokens);
          return null;
        },
        mapProfileToUser: async () => {
          events.push("map");
          throw new Error("Custom getUserInfo must skip the mapper");
        },
      });
      const configured = (await auth.$context).socialProviders.find((value) => value.id === id)!;
      expect(await configured.getUserInfo(tokens)).toBeNull();
      expect(events).toEqual(["custom"]);
    } finally { globalThis.fetch = originalFetch; }
  });
}

for (const id of Object.keys(profiles) as HttpProvider[]) {
  test(`${id} awaits its mapper to supply an omitted profile email`, async () => {
    const profile: Record<string, unknown> = { ...profiles[id].profile };
    delete profile.email;
    const expectedRaw = id === "discord" ? { ...profile, image_url: profiles.discord.defaultUser.image } : profile;
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let mappedProfile: unknown;
    const sample = setup(id, {
      mapProfileToUser: async (raw: unknown) => {
        mappedProfile = raw;
        sample.events.push("map:start");
        started.resolve();
        await release.promise;
        sample.events.push("map:end");
        return { email: mappedEmail };
      },
    });
    try {
      sample.setProfile(profile);
      const configured = (await sample.auth.$context).socialProviders.find((value) => value.id === id)!;
      const pending = configured.getUserInfo(tokens).then((result) => {
        sample.events.push("returned");
        return result;
      });
      await started.promise;
      try {
        expect(mappedProfile).toEqual(expectedRaw);
        expect(Object.hasOwn(mappedProfile as object, "email")).toBe(false);
        expect(sample.events).toEqual(["profile", "map:start"]);
      } finally { release.resolve(); }
      expect(await pending).toEqual({
        user: { ...profiles[id].defaultUser, email: mappedEmail },
        data: expectedRaw,
      });
      expect(sample.events).toEqual(["profile", "map:start", "map:end", "returned"]);
    } finally { release.resolve(); await sample.close(); }
  });
}

const patches: Record<string, EmailPatch> = {
  unchanged: {}, null: { email: null }, undefined: { email: undefined }, string: { email: mappedEmail },
};
for (const rawEmail of ["omitted", "null", "string"] as const) {
  for (const [mapping, patch] of Object.entries(patches)) {
    test(`account-info preserves ${rawEmail} profile email with ${mapping} mapper output`, async () => {
      const sample = setup("huggingface");
      try {
        const cookie = await sample.login();
        const stored = structuredClone(sample.database);
        const account = sample.database.account[0]!;
        const profile: Record<string, unknown> = { ...profiles.huggingface.profile };
        if (rawEmail === "omitted") delete profile.email;
        else if (rawEmail === "null") profile.email = null;
        sample.setProfile(profile);
        sample.setPatch(patch);
        sample.events.length = 0;
        const response = await sample.auth.handler(new Request(
          `${baseURL}/api/auth/account-info?${new URLSearchParams({ accountId: String(account.id) })}`,
          { headers: { cookie } },
        ));
        expect(response.status).toBe(200);
        const expectedEmail = mapping === "unchanged" ? profile.email : patch.email;
        const expectedUser: Record<string, unknown> = { ...profiles.huggingface.defaultUser };
        if (expectedEmail === undefined) delete expectedUser.email;
        else expectedUser.email = expectedEmail;
        expect(await response.json()).toStrictEqual({
          user: expectedUser,
          data: profile,
          account: { id: account.id, providerId: account.providerId, accountId: account.accountId },
        });
        expect(sample.events).toEqual(["profile", "map"]);
        expect(sample.database).toEqual(stored);
      } finally { await sample.close(); }
    });
  }
}

const discordCases = [
  { name: "static avatar uses PNG", patch: {}, image: "https://cdn.discordapp.com/avatars/123456789/portrait.png", userName: "Owner" },
  { name: "animated avatar uses GIF", patch: { avatar: "a_portrait" }, image: "https://cdn.discordapp.com/avatars/123456789/a_portrait.gif", userName: "Owner" },
  { name: "null avatar uses the migrated default", patch: { avatar: null, discriminator: "0" }, image: "https://cdn.discordapp.com/embed/avatars/5.png", userName: "Owner" },
  { name: "null avatar uses the legacy default", patch: { avatar: null, discriminator: "1234" }, image: "https://cdn.discordapp.com/embed/avatars/4.png", userName: "Owner" },
  { name: "global name takes precedence", patch: { global_name: "Global Owner" }, image: "https://cdn.discordapp.com/avatars/123456789/portrait.png", userName: "Global Owner" },
  { name: "empty global name falls back to username", patch: { global_name: "" }, image: "https://cdn.discordapp.com/avatars/123456789/portrait.png", userName: "Owner" },
  { name: "empty global name and username yield an empty name", patch: { global_name: "", username: "" }, image: "https://cdn.discordapp.com/avatars/123456789/portrait.png", userName: "" },
];

for (const sampleCase of discordCases) {
  test(`discord ${sampleCase.name} before passing the profile to its mapper`, async () => {
    const profile = { ...profiles.discord.profile, ...sampleCase.patch };
    const prepared = { ...profile, image_url: sampleCase.image };
    const sample = setup("discord", {
      mapProfileToUser: async (raw: unknown) => {
        sample.events.push("map");
        expect(raw).toEqual(prepared);
        return {};
      },
    });
    try {
      sample.setProfile(profile);
      const configured = (await sample.auth.$context).socialProviders.find((value) => value.id === "discord")!;
      expect(await configured.getUserInfo(tokens)).toEqual({
        user: { ...profiles.discord.defaultUser, name: sampleCase.userName, image: sampleCase.image },
        data: prepared,
      });
      expect(sample.events).toEqual(["profile", "map"]);
    } finally { await sample.close(); }
  });
}

test("generic profile preserves email presence without normalization", async () => {
  const metadata = await Bun.file(new URL("../node_modules/better-auth/package.json", import.meta.url)).json();
  expect(metadata.version).toBe("1.7.6");
  const display = {
    name: "Profile Reader",
    image: "https://images.example.test/profile.png",
    emailVerified: false,
  };
  const cases: { name: string; patch: EmailPatch }[] = [
    { name: "absent", patch: {} },
    { name: "null", patch: { email: null } },
    { name: "empty", patch: { email: "" } },
    { name: "ordinary", patch: { email: "reader@example.test" } },
  ];
  for (const { name, patch } of cases) {
    const profile = { sub: "ordinary-profile", ...display, ...patch };
    let calls = 0;
    const auth = betterAuth({
      secret: "generic-profile-presence-contract-secret-at-least-32-characters",
      baseURL,
      logger: { disabled: true },
      telemetry: { enabled: false },
      plugins: [genericOAuth({ config: [{
        providerId: "profile-presence",
        clientId: "ordinary-profile-client",
        getUserInfo: async () => {
          calls += 1;
          return profile;
        },
      }] })],
    });
    const configured = (await auth.$context).socialProviders.find(value => value.id === "profile-presence");
    if (!configured) throw new Error(`Missing generic profile provider for ${name}`);
    const result = await configured.getUserInfo({});
    const serialized = JSON.parse(JSON.stringify(result));
    expect(Object.hasOwn(serialized.user, "email")).toBe(Object.hasOwn(patch, "email"));
    expect(serialized.user.email).toBe(patch.email);
    expect(serialized.user).toStrictEqual({ ...display, ...patch });
    expect(result?.data).toStrictEqual(profile);
    expect(serialized.data).toStrictEqual(profile);
    expect(calls).toBe(1);
  }
});

test("generic profile preserves name presence and mapper overrides", async () => {
  const metadata = await Bun.file(new URL("../node_modules/better-auth/package.json", import.meta.url)).json();
  expect(metadata.version).toBe("1.7.6");
  const display = {
    email: "reader@example.test",
    image: "https://images.example.test/profile.png",
    emailVerified: false,
  };
  const rawCases: { label: string; patch: Record<string, unknown> }[] = [
    { label: "absent", patch: {} },
    { label: "null", patch: { name: null } },
    { label: "empty", patch: { name: "" } },
    { label: "ordinary", patch: { name: "Profile Reader" } },
  ];
  const mappedCases: { label: string; patch: Record<string, unknown> }[] = [
    { label: "unchanged", patch: {} },
    { label: "undefined", patch: { name: undefined } },
    { label: "null", patch: { name: null } },
    { label: "empty", patch: { name: "" } },
    { label: "ordinary", patch: { name: "Mapped Reader" } },
  ];
  for (const rawCase of rawCases) {
    for (const mappedCase of mappedCases) {
      const profile = { sub: "ordinary-profile", ...display, ...rawCase.patch };
      let handlerCalls = 0;
      let mapperCalls = 0;
      const auth = betterAuth({
        secret: "generic-profile-presence-contract-secret-at-least-32-characters",
        baseURL,
        logger: { disabled: true },
        telemetry: { enabled: false },
        plugins: [genericOAuth({ config: [{
          providerId: "name-presence",
          clientId: "ordinary-profile-client",
          getUserInfo: async () => {
            handlerCalls += 1;
            return profile;
          },
          mapProfileToUser: async (raw) => {
            mapperCalls += 1;
            expect(raw).toStrictEqual(profile);
            return mappedCase.patch;
          },
        }] })],
      });
      const configured = (await auth.$context).socialProviders.find(value => value.id === "name-presence");
      if (!configured) throw new Error(`Missing generic profile provider for ${rawCase.label}/${mappedCase.label}`);
      const result = await configured.getUserInfo({});
      const serialized = JSON.parse(JSON.stringify(result));
      const expectedUser: Record<string, unknown> = { ...display, ...rawCase.patch, ...mappedCase.patch };
      expect(Object.hasOwn(serialized.user, "name")).toBe(expectedUser.name !== undefined);
      expect(serialized.user.name).toBe(expectedUser.name);
      expect(serialized.user).toStrictEqual(JSON.parse(JSON.stringify(expectedUser)));
      expect(result?.data).toStrictEqual(profile);
      expect(serialized.data).toStrictEqual(profile);
      expect(handlerCalls).toBe(1);
      expect(mapperCalls).toBe(1);
    }
  }
});
