import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "@better-auth/memory-adapter";

const results = [];
for (const kind of ["undefined", "duplicate", "changed"] as const) {
  const rows = ["Alice", "Bob"].map((name, index) => ({
    ...(kind === "undefined" ? {} : { id: kind === "duplicate" ? "duplicate" : `${index + 1}` }),
    name, email: `${name.toLowerCase()}@example.com`, emailVerified: false,
    createdAt: new Date("2026-01-01T00:00:00Z"), updatedAt: new Date("2026-01-01T00:00:00Z"),
  }));
  const database = { user: rows, session: [], account: [], verification: [] };
  const auth = betterAuth({
    database: memoryAdapter(database), baseURL: "http://localhost:3000",
    secret: "background-id-contract-secret-at-least-thirty-two-characters",
    advanced: { database: { generateId: false } },
    logger: { disabled: true },
  });
  const { adapter } = await auth.$context;
  const before = structuredClone(database.user);
  let inside;
  await adapter.transaction(async (tx) => {
    await tx.update({ model: "user", where: [{ field: "email", value: "alice@example.com" }],
      update: { name: "Updated Alice", ...(kind === "changed" ? { id: "changed" } : {}) } });
    inside = await tx.findMany({ model: "user" });
  });
  const after = structuredClone(database.user);
  if (kind === "changed") {
    assert.deepEqual(after.map((row) => row.name), ["Bob", "Updated Alice"]);
    assert.equal(after.at(-1)?.id, "changed");
  } else {
    assert.deepEqual(after.map((row) => row.name), ["Alice", "Bob"]);
  }
  assert.equal(inside?.[0]?.name, "Updated Alice");
  results.push({ kind, before, inside, after });
}
console.log(JSON.stringify(results, null, 2));
