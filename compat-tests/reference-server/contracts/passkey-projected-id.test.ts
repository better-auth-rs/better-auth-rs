import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { testUtils } from "better-auth/plugins";
import {
  authenticator, type AuthenticationOptions, type RegistrationOptions,
} from "../../client-tests/tests/phase8/authenticator";
import { withRestoredSchema } from "./schema-isolation.mjs";

for (const name of ["better-auth", "@better-auth/core", "@better-auth/passkey"]) {
  expect(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version).toBe("1.7.6");
}

const origin = "http://passkey-projected-id.test";
const rpID = "passkey-projected-id.test";
const cases: [string, unknown][] = [
  ["different string", Buffer.from("different-credential").toString("base64url")],
  ["null", null],
  ["number", 7],
  ["undefined", undefined],
  ["lone surrogate", "\ud800"],
  ["array", [7]],
  ["object", { id: 7 }],
];
const cookies = (response: Response) => response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");

for (const [label, projected] of cases) {
  test(`authentication preserves ${label} credentialID without bypassing signatures or changing the owner`, async () => {
    await withRestoredSchema(passkey().schema, async () => {
      const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], passkey: [] };
      const trace: unknown[] = [];
      const observations: { verification: any; clientData: unknown }[] = [];
      let replace = false;
      const auth = betterAuth({
        database: memoryAdapter(memory), baseURL: origin,
        secret: "passkey-projected-id-contract-at-least-32-characters",
        logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
        databaseHooks: {
          session: { create: {
            async before(session) { trace.push(["session:before", session.userId]); },
            async after(session) { trace.push(["session:after", session.userId]); },
          } },
        },
        plugins: [passkey({
          rpID, rpName: "Projected credential contract", origin,
          authentication: { afterVerification({ verification, clientData }) {
            trace.push(["verification"]);
            observations.push({ verification, clientData });
          } },
        }), testUtils(), {
          id: "projected-passkey-credential-id",
          schema: { passkey: { fields: {
            credentialID: {
              type: "string", required: false,
              transform: { output(value: unknown) {
                trace.push(["credentialID", value]);
                return replace ? projected : value;
              } },
            },
            counter: {
              type: "number", required: false,
              transform: { output(value: unknown) { trace.push(["counter", value]); return value; } },
            },
          } } },
        }],
      });
      const request = (path: string, cookie?: string, body?: unknown) => {
        const headers = new Headers({ origin, accept: "application/json" });
        if (cookie) headers.set("cookie", cookie);
        if (body !== undefined) headers.set("content-type", "application/json");
        return auth.handler(new Request(`${origin}/api/auth/passkey/${path}`, {
          method: body === undefined ? "GET" : "POST", headers,
          body: body === undefined ? undefined : JSON.stringify(body),
        }));
      };
      const context = await auth.$context;
      const now = new Date();
      const owner = await context.adapter.create<{ id: string }>({ model: "user", forceAllowId: true, data: {
        id: "owner", name: "Owner", email: "owner@passkey-projected-id.test", emailVerified: true,
        image: null, createdAt: now, updatedAt: now,
      } });
      const login = await context.test.login({ userId: owner.id });
      const loginCookie = login.headers.get("cookie");
      expect(loginCookie).toBeString();
      const key = authenticator(`projected-credential-${label}`);
      const registrationResponse = await request("generate-register-options", loginCookie!);
      expect(registrationResponse.status).toBe(200);
      const registrationOptions = await registrationResponse.json() as RegistrationOptions;
      const registered = await request("verify-registration", `${loginCookie}; ${cookies(registrationResponse)}`, {
        response: key.register(registrationOptions, origin, false), name: "Owner passkey",
      });
      expect(registered.status).toBe(200);
      expect(memory.passkey).toHaveLength(1);
      expect(await registered.json()).toStrictEqual(JSON.parse(JSON.stringify(memory.passkey[0])));
      expect(memory.passkey[0].credentialID).toBe(key.id);
      expect(memory.passkey[0].userId).toBe(owner.id);
      expect(memory.passkey[0].counter).toBe(0);
      expect(memory.session).toHaveLength(1);
      const storedPasskeys = structuredClone(memory.passkey);
      const storedUsers = structuredClone(memory.user);
      const storedSessions = structuredClone(memory.session);
      const sessionCookie = `${context.authCookies.sessionToken.name}=`;
      replace = true;

      for (const valid of [false, true]) {
        trace.length = 0;
        observations.length = 0;
        const optionsResponse = await request("generate-authenticate-options");
        expect(optionsResponse.status).toBe(200);
        const options = await optionsResponse.json() as AuthenticationOptions;
        const assertion = key.authenticate(options, origin, 1, 0x01, registrationOptions.user.id);
        if (!valid) {
          const signature = Buffer.from(assertion.response.signature, "base64url");
          signature[signature.length - 1] ^= 1;
          assertion.response.signature = signature.toString("base64url");
        }
        const response = await request("verify-authentication", cookies(optionsResponse), { response: assertion });
        expect(memory.user).toStrictEqual(storedUsers);
        expect(memory.verification).toStrictEqual([]);
        if (!valid) {
          expect(response.status).toBe(401);
          expect(await response.json()).toStrictEqual({ code: "AUTHENTICATION_FAILED", message: "Authentication failed" });
          expect(observations).toStrictEqual([]);
          expect(trace).toStrictEqual([["credentialID", key.id], ["counter", 0]]);
          expect(memory.passkey).toStrictEqual(storedPasskeys);
          expect(memory.session).toStrictEqual(storedSessions);
          expect(response.headers.getSetCookie().some(value => value.startsWith(sessionCookie))).toBe(false);
          continue;
        }
        expect(response.status).toBe(200);
        expect(trace).toStrictEqual([
          ["credentialID", key.id], ["counter", 0], ["verification"],
          ["credentialID", key.id], ["counter", 1],
          ["session:before", owner.id], ["session:after", owner.id],
        ]);
        expect(observations).toHaveLength(1);
        expect(observations[0].clientData).toStrictEqual(assertion);
        expect(observations[0].verification).toStrictEqual({
          verified: true,
          authenticationInfo: {
            newCounter: 1, credentialID: projected, userVerified: false,
            credentialDeviceType: "singleDevice", credentialBackedUp: false,
            authenticatorExtensionResults: undefined, origin, rpID,
          },
        });
        expect(observations[0].verification.authenticationInfo.credentialID).toBe(projected);
        expect(memory.passkey).toStrictEqual(storedPasskeys.map(row => ({ ...row, counter: 1 })));
        expect(memory.session).toHaveLength(storedSessions.length + 1);
        expect(memory.session.slice(0, storedSessions.length)).toStrictEqual(storedSessions);
        const session = memory.session.at(-1)!;
        expect(session.userId).toBe(owner.id);
        expect(await response.json()).toStrictEqual(JSON.parse(JSON.stringify({ session, user: storedUsers[0] })));
        expect(response.headers.getSetCookie().some(value => value.startsWith(sessionCookie))).toBe(true);
      }
    });
  });
}
