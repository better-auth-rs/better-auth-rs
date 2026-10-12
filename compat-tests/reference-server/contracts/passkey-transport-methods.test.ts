import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { testUtils } from "better-auth/plugins";
import { createTransport, transportCases, transportFails } from "./passkey-transport-methods-shared.mjs";
import { withRestoredSchema } from "./schema-isolation.mjs";

const origin = "http://passkey-transport-methods.test";

for (const name of transportCases) {
  test(`Passkey options preserve ${name} split semantics through serialization`, async () => {
    await withRestoredSchema(passkey().schema, async () => {
      const transport = createTransport(name);
      const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], passkey: [] };
      let active = false;
      const auth = betterAuth({
        baseURL: origin, database: memoryAdapter(memory),
        secret: "passkey-transport-methods-secret-at-least-thirty-two",
        logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
        session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
        plugins: [passkey({ rpID: "passkey-transport-methods.test", rpName: "Transport methods" }), testUtils(), {
          id: "passkey-transport-method-options", schema: { passkey: { fields: {
            transports: { type: "string", required: false, transform: { output: value => active ? transport.receiver : value } },
          } } },
        }],
      });
      const context = await auth.$context;
      const now = new Date();
      const owner = await context.adapter.create<{ id: string }>({ model: "user", forceAllowId: true, data: {
        id: "owner", name: "Owner", email: "transport@passkey-transport-methods.test", emailVerified: true,
        image: null, createdAt: now, updatedAt: now,
      } });
      const login = await context.test.login({ userId: owner.id });
      const credentialID = Buffer.from("transport-options").toString("base64url");
      await context.adapter.create({ model: "passkey", data: {
        userId: owner.id, name: "Native authenticator", publicKey: "unused by options", credentialID,
        counter: 0, deviceType: "singleDevice", backedUp: false, transports: "internal", createdAt: now,
      } });
      const before = structuredClone(memory);
      active = true;
      for (const [method, property] of [
        ["generatePasskeyRegistrationOptions", "excludeCredentials"],
        ["generatePasskeyAuthenticationOptions", "allowCredentials"],
      ] as const) {
        transport.events.length = 0;
        const challenges = structuredClone(memory.verification);
        let result: any;
        let caught: any;
        try {
          result = await auth.api[method]({ headers: login.headers });
        } catch (error) {
          if (error instanceof assert.AssertionError) throw error;
          caught = error;
        }
        transport.assertCalls();
        if (transportFails(name)) {
          if (name === "noncallable") {
            expect(caught).toBeInstanceOf(TypeError);
            expect(caught.message).toBe('passkey.transports?.split is not a function. (In \'passkey.transports?.split(",")\', \'passkey.transports?.split\' is 17)');
          } else expect(caught).toBe(transport.original);
          expect(memory.verification).toStrictEqual(challenges);
        } else {
          expect(caught).toBeUndefined();
          expect(result[property]).toHaveLength(1);
          const descriptor = result[property][0];
          expect(Object.keys(descriptor)).toStrictEqual(["id", "transports", "type"]);
          expect(descriptor).toStrictEqual({ id: credentialID, transports: transport.result, type: "public-key" });
          expect(descriptor.transports).toBe(transport.result);
          transport.assertCalls();
          if (name === "unread-result") {
            assert.throws(() => JSON.stringify(result), error => error === transport.original);
            expect(transport.events).toStrictEqual(["split:get", "split:call", "result:read"]);
          } else {
            expect(JSON.parse(JSON.stringify(result))[property]).toStrictEqual([
              { id: credentialID, ...(transport.result === undefined ? {} : { transports: JSON.parse(JSON.stringify(transport.result)) }), type: "public-key" },
            ]);
            transport.assertCalls();
          }
          expect(memory.verification).toHaveLength(challenges.length + 1);
        }
        expect(memory.passkey).toStrictEqual(before.passkey);
        expect(memory.user).toStrictEqual(before.user);
        expect(memory.session).toStrictEqual(before.session);
        expect(memory.account).toStrictEqual(before.account);
      }
    });
  });
}

for (const name of ["better-auth", "@better-auth/core", "@better-auth/passkey"]) {
  expect(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version).toBe("1.7.6");
}
