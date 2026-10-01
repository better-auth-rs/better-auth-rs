import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { Database } from "bun:sqlite";

const results = [];
const scenarios = [
  { failures: ["name:A"], extraCount: 0, trace: ["name:A", "name:B", "image:B.png"] },
  { failures: ["name:B"], extraCount: 0, trace: ["name:A", "name:B", "image:A.png"] },
  { failures: ["image:A.png"], extraCount: 0, trace: ["name:A", "name:B", "image:A.png", "image:B.png"] },
  { failures: ["name:B", "image:A.png"], extraCount: 0, trace: ["name:A", "name:B", "image:A.png"] },
  { failures: ["name:A", "name:B"], extraCount: 0, trace: ["name:A", "name:B"] },
  { failures: ["name:A"], extraCount: 8, trace: ["name:A", "name:B", "image:B.png", "extra0:B-0", "extra1:B-1", "extra2:B-2"] },
  { failures: ["name:B"], extraCount: 8, trace: ["name:A", "name:B", "image:A.png", "extra0:A-0", "extra1:A-1", "extra2:A-2", "extra3:A-3"] },
];
for (const scenario of scenarios) {
const { failures, extraCount } = scenario;
for (const backend of ["memory", "sqlite"] as const) {
  const trace: string[] = [];
  let armed = false;
  const field = (name: string) => ({
    type: "string" as const,
    transform: { output(value: unknown) {
      const event = `${name}:${value}`;
      trace.push(event);
      if (armed && failures.includes(event)) throw new Error(event);
      return `${value}:${trace.length}`;
    } },
  });
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = {
    database: database ?? memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    baseURL: "http://transform.test", secret: "transform-order-fixture-secret-at-least-32-characters",
    logger: { disabled: true }, user: { additionalFields: { name: field("name"), image: field("image"), ...Object.fromEntries(Array.from({ length: extraCount }, (_, i) => [`extra${i}`, field(`extra${i}`)])) } },
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const { adapter } = await betterAuth(options).$context;
  for (const name of ["A", "B"]) {
    await adapter.create({ model: "user", data: {
      name, image: `${name}.png`, ...Object.fromEntries(Array.from({ length: extraCount }, (_, i) => [`extra${i}`, `${name}-${i}`])), email: `${name.toLowerCase()}@transform.test`, emailVerified: false,
      createdAt: new Date("2020-01-01"), updatedAt: new Date("2020-01-01"),
    } });
  }
  trace.length = 0;
  armed = true;
  let message: string | undefined;
  try {
    await adapter.findMany({ model: "user", sortBy: { field: "email", direction: "asc" } });
  } catch (error) {
    message = (error as Error).message;
  }
  assert.equal(message, failures[0]);
  assert.deepEqual(trace, scenario.trace);
  results.push({ backend, failures, extraCount, trace: [...trace], message });
  database?.close();
}
}
console.log(JSON.stringify(results));
