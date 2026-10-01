import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { passkey } from "@better-auth/passkey";
import { apiKey } from "@better-auth/api-key";
import { memoryAdapter } from "better-auth/adapters/memory";
import { Database } from "bun:sqlite";
import { getMigrations } from "better-auth/db/migration";

test("ordinary plugin creation preserves timestamps before name input and generates IDs afterward", async () => {
  for (const backend of ["memory", "sqlite"]) {
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const memory = { user: [], session: [], account: [], verification: [], passkey: [], apikey: [] };
    const events = [];
    let id = 0;
    const field = {
      type: "string",
      transform: {
        input: async value => {
          events.push("name:input");
          return value;
        },
        output: value => {
          events.push("name:output");
          return value;
        },
      },
    };
    const opts = {
      database: database ?? memoryAdapter(memory),
      secret: "ordinary-create-order-fixture-at-least-32-characters",
      baseURL: "http://create-order.test",
      logger: { disabled: true },
      advanced: {
        database: {
          generateId: ({ model }) => {
            events.push(`id:${model}`);
            return `ordinary-${++id}`;
          },
        },
      },
      plugins: [
        passkey(),
        apiKey(),
        {
          id: "ordinary-create-order",
          schema: { passkey: { fields: { name: field } }, apikey: { fields: { name: field } } },
        },
      ],
    };
    if (database) await (await getMigrations(opts)).runMigrations();
    const { adapter } = await betterAuth(opts).$context;
    const user = await adapter.create({
      model: "user",
      data: {
        name: "Owner",
        email: "ordinary@create-order.test",
        emailVerified: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    });
    for (const model of ["passkey", "apikey"]) {
      events.length = 0;
      const createdAt = new Date();
      events.push("timestamp:input");
      const data = model === "passkey"
        ? {
            name: "Desk", userId: user.id, credentialID: "ordinary-credential",
            publicKey: "ordinary-public-key", counter: 0, deviceType: "singleDevice",
            backedUp: false, createdAt,
          }
        : {
            name: "Desk", configId: "default", referenceId: user.id, key: "ordinary-hash",
            enabled: true, rateLimitEnabled: false, requestCount: 0, createdAt, updatedAt: createdAt,
          };
      const row = await adapter.create({ model, data });
      expect(events).toStrictEqual(["timestamp:input", "name:input", `id:${model}`, "name:output"]);
      expect(new Date(row.createdAt).getTime()).toBe(createdAt.getTime());
      expect(row.name).toBe("Desk");
    }
    database?.close();
  }
});
