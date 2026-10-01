import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { Database } from "bun:sqlite";

export async function observeTransformOrder() {
  const results = [];
  for (const backend of ["memory", "sqlite"] as const) {
    const trace: string[] = [];
    const field = (name: string) => ({
      type: "string" as const,
      transform: { output(value: unknown) {
        trace.push(`${name}:${value}`);
        return `${value}:${trace.length}`;
      } },
    });
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const options = {
      database: database ?? memoryAdapter({ user: [], session: [], account: [], verification: [] }),
      baseURL: "http://transform.test", secret: "transform-order-fixture-secret-at-least-32-characters",
      logger: { disabled: true }, user: { additionalFields: { name: field("name"), image: field("image") } },
    };
    if (database) await (await getMigrations(options)).runMigrations();
    const { adapter } = await betterAuth(options).$context;
    for (const name of ["A", "B"]) {
      await adapter.create({ model: "user", data: {
        name, image: `${name}.png`, email: `${name.toLowerCase()}@transform.test`, emailVerified: false,
        createdAt: new Date("2020-01-01"), updatedAt: new Date("2020-01-01"),
      } });
    }
    trace.length = 0;
    const rows = await adapter.findMany({ model: "user", sortBy: { field: "email", direction: "asc" } });
    assert.deepEqual(trace, ["name:A", "name:B", "image:A.png", "image:B.png"]);
    const values = rows.map((row: any) => ({ name: row.name, image: row.image }));
    assert.deepEqual(values, [{ name: "A:1", image: "A.png:3" }, { name: "B:2", image: "B.png:4" }]);
    results.push({ backend, trace, values });
    database?.close();
  }
  return results;
}

if (import.meta.main) console.log(JSON.stringify(await observeTransformOrder()));
