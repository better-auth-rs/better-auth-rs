import assert from "node:assert/strict";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

export async function withDeviceGrantDatabase(backend, configuration, run) {
  assert.ok(["memory", "sqlite", "postgres", "mysql"].includes(backend));
  if (backend === "memory") {
    const memory = { user: [], session: [], account: [], verification: [], deviceCode: [] };
    return await run(betterAuth({ ...configuration, database: memoryAdapter(memory) }));
  }
  if (backend === "sqlite") {
    const database = new Database(":memory:");
    try {
      const options = { ...configuration, database };
      await (await getMigrations(options)).runMigrations();
      return await run(betterAuth(options));
    } finally {
      database.close();
    }
  }
  const captured = await captureFreshServerCatalog(backend, ["deviceCode"], configuration,
    ({ options }) => run(betterAuth(options)));
  return captured.observation;
}
