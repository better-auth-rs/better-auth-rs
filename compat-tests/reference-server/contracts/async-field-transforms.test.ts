import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import expected from "../../../tests/fixtures/async-transform-upstream.json";

test("ordinary awaited output callbacks advance rows independently and preserve result order", async () => {
  const observed: Record<string, unknown> = {};
  for (const backend of ["memory", "sqlite"] as const) {
    let armed = false;
    const trace: string[] = [];
    const phases = new Map(["name:A", "name:B", "image:A.png", "image:B.png"].map(key => [key, {
      started: Promise.withResolvers<void>(), result: Promise.withResolvers<unknown>(),
    }]));
    const field = (name: string) => ({ type: "string" as const, transform: {
      async output(value: unknown) {
        if (!armed) return value;
        const key = `${name}:${value}`;
        const phase = phases.get(key);
        if (!phase) throw new Error(`Unexpected ordinary fixture field ${key}`);
        trace.push(key);
        phase.started.resolve();
        return await phase.result.promise;
      },
    } });
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const options = {
      database: database ?? memoryAdapter({ user: [], session: [], account: [], verification: [] }),
      baseURL: "http://async-transform.test", secret: "async-field-fixture-secret-at-least-32-characters",
      logger: { disabled: true }, user: { additionalFields: { name: field("name"), image: field("image") } },
    };
    if (database) await (await getMigrations(options)).runMigrations();
    const { adapter } = await betterAuth(options).$context;
    for (const name of ["A", "B"]) {
      await adapter.create({ model: "user", data: {
        name, image: `${name}.png`, email: `${name.toLowerCase()}@async-transform.test`, emailVerified: false,
        createdAt: new Date("2020-01-01"), updatedAt: new Date("2020-01-01"),
      } });
    }
    const phase = (key: string) => {
      const value = phases.get(key);
      if (!value) throw new Error(`Missing ordinary fixture phase ${key}`);
      return value;
    };
    armed = true;
    const pending = adapter.findMany({ model: "user", sortBy: { field: "email", direction: "asc" } });
    await Promise.all([phase("name:A").started.promise, phase("name:B").started.promise]);
    phase("name:B").result.resolve("B:resolved");
    await phase("image:B.png").started.promise;
    phase("image:B.png").result.resolve("B.png:resolved");
    phase("name:A").result.resolve("A:resolved");
    await phase("image:A.png").started.promise;
    phase("image:A.png").result.resolve("A.png:resolved");
    const rows = await pending;
    observed[backend] = { trace, values: rows.map((row: any) => ({ name: row.name, image: row.image })) };
    database?.close();
  }
  expect(observed).toStrictEqual(expected);
});
