import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { passkey } from "@better-auth/passkey";
import { serializeSignedCookie } from "better-call";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { authenticator, type RegistrationOptions } from "../../client-tests/tests/phase8/authenticator";
import cases from "../../../tests/fixtures/passkey-user-id-cases.json";
import { revive } from "./user-runtime-contract";
import { withRestoredSchema } from "./schema-isolation.mjs";

const origin = "https://passkey.example";
const rpID = "passkey.example";
const secret = "passkey-native-owner-contract-at-least-thirty-two-characters";
const credentialID = Buffer.from("ordinary-native-passkey").toString("base64url");
const cookies = (response: Response) => response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");

async function setup(sqlite: boolean, existing: boolean, passkeyOwner?: object) {
  const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], passkey: [] };
  const database = sqlite ? new Database(":memory:") : undefined;
  const sessions = new Map<string, string>();
  const options = {
    database: database ?? memoryAdapter(memory), baseURL: origin,
    secret,
    secondaryStorage: {
      async get(key: string) { return sessions.get(key) ?? null; },
      async set(key: string, value: string) { sessions.set(key, value); },
      async delete(key: string) { sessions.delete(key); },
      async getAndDelete(key: string) { const value = sessions.get(key) ?? null; sessions.delete(key); return value; },
    },
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { storeSessionInDatabase: true },
    plugins: [passkey({ rpID, rpName: "Passkey native owner", origin }), ...(passkeyOwner ? [{
      id: "native-passkey-owner", schema: { passkey: { fields: {
        userId: { type: "string" as const, transform: { output: () => passkeyOwner } },
      } } },
    }] : [])],
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context = await auth.$context;
  const now = new Date();
  const user = await context.adapter.create({ model: "user", forceAllowId: true, data: {
    id: "7", name: "Owner", email: "owner@passkey.example", emailVerified: false,
    createdAt: now, updatedAt: now,
  } });
  const session = await context.internalAdapter.createSession("7");
  if (existing) await context.adapter.create({ model: "passkey", data: {
    userId: "7", name: "Existing", credentialID, publicKey: "unused by options", counter: 0,
    deviceType: "singleDevice", backedUp: false, transports: "internal,hybrid", createdAt: now,
  } });
  const request = (path: string, cookie?: string, body?: unknown) => auth.handler(new Request(`${origin}/api/auth${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { origin, ...(cookie ? { cookie } : {}), ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  }));
  return {
    memory, context, request, close() { database?.close(); },
    async issue(id: unknown) {
      sessions.set(session.token, JSON.stringify({
        session: { ...session, expiresAt: new Date("2100-01-01T00:00:00.000Z") },
        user: { ...user, id },
      }));
      return (await serializeSignedCookie(context.authCookies.sessionToken.name, session.token, secret)).split(";", 1)[0];
    },
  };
}

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} Passkey options and lists consume native IDs from signed session snapshots`, async () => {
    await withRestoredSchema(passkey().schema, async () => {
      const fixture = await setup(backend === "sqlite", true);
      try {
        const stored = await fixture.context.adapter.findMany({ model: "passkey" });
        for (const sample of cases) {
          const count = backend === "sqlite" ? sample.sqliteMatches : sample.memoryMatches;
          if (count === undefined) continue;
          const cookie = await fixture.issue(revive(sample.value));
          const listed = await fixture.request("/passkey/list-user-passkeys", cookie);
          expect(listed.status).toBe(200);
          expect(await listed.json()).toStrictEqual(JSON.parse(JSON.stringify(count ? stored : [])));
          const authentication = await fixture.request("/passkey/generate-authenticate-options", cookie);
          expect(authentication.status).toBe(200);
          const descriptors = [{ id: credentialID, type: "public-key", transports: ["internal", "hybrid"] }];
          expect((await authentication.json()).allowCredentials).toStrictEqual(count ? descriptors : undefined);
          const registration = await fixture.request("/passkey/generate-register-options", cookie);
          expect(registration.status).toBe(sample.registration);
          const result = await registration.json();
          if (sample.registration === 401) {
            expect(result).toStrictEqual({ code: "SESSION_REQUIRED", message: "Passkey registration requires an authenticated session" });
          } else {
            expect(result.excludeCredentials).toStrictEqual(count ? descriptors : []);
            expect(Buffer.from(result.user.id, "base64url").toString()).toMatch(/^[a-z0-9]{32}$/);
          }
        }
        expect(await fixture.context.adapter.findMany({ model: "passkey" })).toStrictEqual(stored);
      } finally { fixture.close(); }
    });
  });

  test(`${backend} Passkey mutations require a truthy strict owner and preserve rejected records`, async () => {
    await withRestoredSchema(passkey().schema, async () => {
      const fixture = await setup(backend === "sqlite", true);
      try {
        const [original] = await fixture.context.adapter.findMany<any>({ model: "passkey" });
        const rejectBoth = async (cookie: string, id: string, status: number, body?: unknown) => {
          for (const path of ["/passkey/update-passkey", "/passkey/delete-passkey"]) {
            const rejected = await fixture.request(path, cookie, { id, name: "Unauthorized" });
            expect(rejected.status).toBe(status);
            if (body === undefined) expect(await rejected.text()).toBe("");
            else expect(await rejected.json()).toStrictEqual(body);
            expect(await fixture.context.adapter.findMany({ model: "passkey" })).toStrictEqual([original]);
          }
        };
        for (const sample of cases) {
          if (backend === "sqlite" && sample.sqliteMatches === undefined) continue;
          const owner = revive(sample.value);
          if (owner === "7") continue;
          const cookie = await fixture.issue(owner);
          if (!owner) {
            for (const id of [original.id, "missing", ""]) await rejectBoth(cookie, id, 401);
          } else {
            const update = await fixture.request("/passkey/update-passkey", cookie, { id: original.id, name: "Unauthorized" });
            expect(update.status).toBe(401);
            expect(await update.json()).toStrictEqual({
              code: "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY", message: "You are not allowed to register this passkey",
            });
            const deletion = await fixture.request("/passkey/delete-passkey", cookie, { id: original.id });
            expect(deletion.status).toBe(401);
            expect(await deletion.text()).toBe("");
          }
          expect(await fixture.context.adapter.findMany({ model: "passkey" })).toStrictEqual([original]);
        }
        const cookie = await fixture.issue("7");
        await rejectBoth(cookie, "", 400, { message: "Missing required parameter: id" });
        await rejectBoth(cookie, "missing", 404, { code: "PASSKEY_NOT_FOUND", message: "Passkey not found" });
        const update = await fixture.request("/passkey/update-passkey", cookie, { id: original.id, name: "Renamed" });
        expect(update.status).toBe(200);
        expect(await update.json()).toStrictEqual({ passkey: JSON.parse(JSON.stringify({ ...original, name: "Renamed" })) });
        expect(await fixture.context.adapter.findMany({ model: "passkey" })).toStrictEqual([{ ...original, name: "Renamed" }]);
        const deletion = await fixture.request("/passkey/delete-passkey", cookie, { id: original.id });
        expect(deletion.status).toBe(200);
        expect(await deletion.json()).toStrictEqual({ status: true });
        expect(await fixture.context.adapter.findMany({ model: "passkey" })).toStrictEqual([]);
      } finally { fixture.close(); }
    });
  });
}

test("equal object contents do not authorize Passkey mutations", async () => {
  await withRestoredSchema(passkey().schema, async () => {
    const owner = { owner: 7 };
    const fixture = await setup(false, true, owner);
    try {
      const original = structuredClone(fixture.memory.passkey);
      const cookie = await fixture.issue(owner);
      const update = await fixture.request("/passkey/update-passkey", cookie, { id: original[0].id, name: "Unauthorized" });
      expect(update.status).toBe(401);
      expect(await update.json()).toStrictEqual({
        code: "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY", message: "You are not allowed to register this passkey",
      });
      const deletion = await fixture.request("/passkey/delete-passkey", cookie, { id: original[0].id });
      expect(deletion.status).toBe(401);
      expect(await deletion.text()).toBe("");
      expect(fixture.memory.passkey).toStrictEqual(original);
    } finally { fixture.close(); }
  });
});

test("signed registration retains native owners and rejects JSON-changed object identity", async () => {
  await withRestoredSchema(passkey().schema, async () => {
    for (const createSession of [false, true]) {
      for (const sample of cases) {
        if (!("verification" in sample)) continue;
        const expected = createSession ? sample.sessionVerification : sample.verification;
        const fixture = await setup(false, false);
        try {
          const value = revive(sample.value);
          const cookie = await fixture.issue(value);
          const generation = await fixture.request("/passkey/generate-register-options", cookie);
          expect(generation.status).toBe(200);
          const options = await generation.json() as RegistrationOptions;
          const key = authenticator(`native-owner-${sample.name}`);
          const signed = { response: key.register(options, origin, false), name: "Native owner", createSession };
          const challengeCookie = `${cookie}; ${cookies(generation)}`;
          const verified = await fixture.request("/passkey/verify-registration", challengeCookie, signed);
          expect(verified.status).toBe(expected);
          if (expected === 200) {
            expect(fixture.memory.passkey).toHaveLength(1);
            expect(fixture.memory.passkey[0].userId).toBe(value);
            expect(fixture.memory.passkey[0].counter).toBe(0);
            const result = await verified.json();
            expect(result.userId).toBe(String(value));
            if (createSession) expect([result.user.id, result.session.userId]).toStrictEqual(["7", "7"]);
          } else {
            expect(fixture.memory.passkey).toStrictEqual([]);
            expect(await verified.json()).toStrictEqual(expected === 500 ? {
              code: "USER_NOT_FOUND", message: "User not found",
            } : {
              code: "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY", message: "You are not allowed to register this passkey",
            });
          }
          const replay = await fixture.request("/passkey/verify-registration", challengeCookie, signed);
          expect(replay.status).toBe(400);
          expect(await replay.json()).toStrictEqual({ code: "CHALLENGE_NOT_FOUND", message: "Challenge not found" });
          expect(fixture.memory.verification).toStrictEqual([]);
          expect(fixture.memory.session).toHaveLength(createSession && expected === 200 ? 2 : 1);
        } finally { fixture.close(); }
      }
    }
  });
});
