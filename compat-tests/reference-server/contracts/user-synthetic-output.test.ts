import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { buildSyntheticUserOutput } from "better-auth/db";
import { getMigrations } from "better-auth/db/migration";
import { getCurrentAdapter } from "@better-auth/core/context";

test("synthetic User output uses complete declarations and preserves undefined factory results", () => {
  const events: string[] = [];
  const optional = (defaultValue?: unknown) => ({ type: "string" as const, required: false, defaultValue });
  const options = {
    user: { additionalFields: {
      emailVerified: optional(), provided: optional("fallback"), fallback: optional("default"),
      noDefault: optional(undefined),
      factory: { ...optional(), defaultValue: () => { events.push("factory"); return undefined; } },
      required: { type: "string" as const, required: true, defaultValue: undefined },
      hidden: { type: "string" as const, returned: false, defaultValue: () => { throw new Error("hidden factory ran"); } },
      id: { type: "string" as const, returned: false },
      pluginChoice: optional("application"),
    } },
    plugins: [{ id: "synthetic-declaration", schema: { user: { fields: { pluginChoice: optional("plugin") } } } }],
  };
  const date = new Date(0);
  const id = { native: true };
  const output = buildSyntheticUserOutput(options, {
    id, name: "Owner", email: "owner@synthetic.test", emailVerified: undefined,
    createdAt: date, updatedAt: date, provided: null, fallback: undefined, unknown: "omit",
  });
  const expected = {
    name: "Owner", email: "owner@synthetic.test", emailVerified: null, image: null,
    createdAt: date, updatedAt: date, pluginChoice: "plugin", provided: null,
    fallback: "default", noDefault: null, factory: undefined, id,
  };
  expect(output).toStrictEqual(expected);
  expect(Object.keys(output)).toStrictEqual(Object.keys(expected));
  expect(output.id).toBe(id);
  expect(output.createdAt).toBe(date);
  expect(output.updatedAt).toBe(date);
  expect(events).toStrictEqual(["factory"]);
});

test("duplicate signup filters the custom synthetic User without changing stored rows", async () => {
  const date = new Date(0);
  const memory = { user: [{
    id: "existing-user", name: "Existing", email: "owner@synthetic.test", emailVerified: true,
    image: null, createdAt: date, updatedAt: date,
  }], session: [], account: [], verification: [] };
  const before = structuredClone(memory);
  const auth = betterAuth({
    baseURL: "http://localhost:3000", secret: "synthetic-route-secret-at-least-thirty-two-characters",
    database: memoryAdapter(memory), logger: { disabled: true }, telemetry: { enabled: false },
    user: { additionalFields: {
      id: { type: "string", required: false, returned: false },
      fallback: { type: "string", required: false, defaultValue: "default" },
      factory: { type: "string", required: false, defaultValue: () => undefined },
      choice: { type: "string", required: false, defaultValue: "application" },
      username: { type: "string", required: false, defaultValue: "application-user" },
    } },
    plugins: [{ id: "synthetic-provenance", schema: { user: { fields: {
      choice: { type: "string", required: false, defaultValue: "plugin" },
      pluginOnly: { type: "string", required: false, defaultValue: "plugin-only" },
    } } } }],
    emailAndPassword: {
      enabled: true, autoSignIn: false,
      password: {
        hash: async (password) => `hashed:${password}`,
        verify: async ({ hash, password }) => hash === `hashed:${password}`,
      },
      customSyntheticUser: ({ coreFields, additionalFields, id }) => {
        expect(additionalFields).toStrictEqual({ fallback: "default", factory: undefined, choice: "plugin", username: "application-user" });
        expect(Object.keys(additionalFields)).toStrictEqual(["fallback", "factory", "choice", "username"]);
        return { ...coreFields, id, createdAt: date, updatedAt: date, fallback: undefined, factory: undefined };
      },
    },
  });
  const response = await auth.handler(new Request("http://localhost:3000/api/auth/sign-up/email", {
    method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:3000" },
    body: JSON.stringify({ name: "Submitted", email: "owner@synthetic.test", password: "Password123!" }),
  }));
  expect(response.status).toBe(200);
  expect(await response.json()).toStrictEqual({ token: null, user: {
    name: "Submitted", email: "owner@synthetic.test", emailVerified: false, image: null,
    createdAt: date.toISOString(), updatedAt: date.toISOString(), fallback: "default",
    choice: "plugin", pluginOnly: "plugin-only", username: "application-user",
  } });
  expect(response.headers.get("set-cookie")).toBeNull();
  expect(memory).toStrictEqual(before);
});

for (const sqlite of [false, true]) {
  for (const mode of ["success", "factory", "default"] as const) {
    test(`${sqlite ? "SQLite" : "Memory"}: synthetic ${mode} controls commit of protected signup hook writes`, async () => {
      const database = sqlite ? new Database(":memory:") : undefined;
      const memory = { user: [], session: [], account: [], verification: [] };
      const events: string[] = [];
      let denied = false;
      const date = new Date(0);
      const options = {
        baseURL: "http://localhost:3000", secret: "synthetic-transaction-secret-at-least-thirty-two-characters",
        database: database ?? memoryAdapter(memory), logger: { disabled: true }, telemetry: { enabled: false },
        user: { additionalFields: { probe: {
          type: "string" as const, required: false, defaultValue: () => {
            if (denied) {
              events.push("default");
              if (mode === "default") throw new Error("synthetic default failed");
            }
            return "parsed";
          },
        } } },
        emailAndPassword: {
          enabled: true, autoSignIn: false,
          password: {
            hash: async (password: string) => `hashed:${password}`,
            verify: async ({ hash, password }: { hash: string; password: string }) => hash === `hashed:${password}`,
          },
          customSyntheticUser: ({ coreFields, id }: any) => {
            events.push("factory");
            if (mode === "factory") throw new Error("synthetic factory failed");
            return { ...coreFields, id, createdAt: date, updatedAt: date };
          },
        },
        databaseHooks: { user: { create: { async before(_user: any, context: any) {
          events.push("before");
          const tx = await getCurrentAdapter(context.context.adapter);
          await tx.create({ model: "verification", data: {
            identifier: "synthetic-effect", value: "written-before-denial",
            expiresAt: new Date(Date.now() + 3_600_000), createdAt: date, updatedAt: date,
          } });
          expect(await tx.count({ model: "verification" })).toBe(1);
          events.push("write");
          denied = true;
          throw new APIError("FORBIDDEN", { code: "APPLICATION_DENIED", message: "Application denied user" });
        } } } },
      };
      try {
        if (database) await (await getMigrations(options)).runMigrations();
        const auth = betterAuth(options);
        const response = await auth.handler(new Request("http://localhost:3000/api/auth/sign-up/email", {
          method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:3000" },
          body: JSON.stringify({ name: "Denied", email: "denied@synthetic.test", password: "Password123!" }),
        }));
        expect(response.status).toBe(mode === "success" ? 200 : 500);
        if (mode === "success") expect((await response.json()).user.probe).toBe("parsed");
        else expect(await response.text()).toBe("");
        expect(events).toStrictEqual(mode === "factory" ? ["before", "write", "factory"] : ["before", "write", "factory", "default"]);
        const { adapter } = await auth.$context;
        const effects = await adapter.findMany<any>({ model: "verification" });
        expect(effects.map(row => row.value)).toStrictEqual(mode === "success" ? ["written-before-denial"] : []);
        for (const model of ["user", "account", "session"]) expect(await adapter.count({ model })).toBe(0);
      } finally { database?.close(); }
    });
  }
}
