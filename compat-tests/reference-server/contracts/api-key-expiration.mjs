import assert from "node:assert/strict";
import { Database } from "bun:sqlite";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { getMigrations } from "better-auth/db/migration";

const cases = [
  { name: "default-omitted", keyExpiration: {} },
  { name: "default-zero", keyExpiration: { defaultExpiresIn: 0 } },
  { name: "default-fractional", keyExpiration: { defaultExpiresIn: 1.5 } },
  { name: "range-boundaries", keyExpiration: { minExpiresIn: 0.5, maxExpiresIn: 1.5 }, createExpiresIn: 43200, updateExpiresIn: 129600 },
  { name: "range-fractional", keyExpiration: { defaultExpiresIn: 1.5, minExpiresIn: 0.5, maxExpiresIn: 1.5 }, createExpiresIn: 86400.25, updateExpiresIn: 64800.5 },
];

const results = [];
for (const input of cases) {
  const database = new Database(":memory:");
  const options = {
    database, baseURL: "http://key-expiration.test",
    secret: "ordinary-key-expiration-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [apiKey({ keyExpiration: input.keyExpiration })],
  };
  const originalNow = Date.now;
  try {
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const context = await auth.$context;
    const user = await context.internalAdapter.createUser({
      name: "Expiration Owner", email: "owner@key-expiration.test", emailVerified: false,
    });
    const now = originalNow();
    Date.now = () => now;
    const project = (row) => ({
      name: row.name,
      lifetimeMillis: row.expiresAt === null ? null : new Date(row.expiresAt).getTime() - now,
    });
    const raw = (id) => database.query("SELECT name, expiresAt FROM apikey WHERE id = ?").get(id);
    const created = await auth.api.createApiKey({ body: {
      userId: user.id, name: "Desk", expiresIn: input.createExpiresIn,
    } });
    const storedCreated = project(raw(created.id));
    const updated = await auth.api.updateApiKey({ body: {
      userId: user.id, keyId: created.id, name: "Mobile", expiresIn: input.updateExpiresIn,
    } });
    results.push({ ...input, created: project(created), storedCreated,
      updated: project(updated), storedUpdated: project(raw(created.id)) });
  } finally {
    Date.now = originalNow;
    database.close();
  }
}

const fixture = new URL("../../../tests/fixtures/api-key-expiration-1.7.6.json", import.meta.url);
if (process.env.API_KEY_EXPIRATION_OUTPUT) {
  writeFileSync(process.env.API_KEY_EXPIRATION_OUTPUT, JSON.stringify(results, null, 2) + "\n");
  console.log(`Captured ${results.length} ordinary SQLite API Key expiration configuration cases`);
} else {
  assert.deepEqual(results, JSON.parse(readFileSync(fixture, "utf8")));
  console.log(`${results.length} ordinary SQLite API Key expiration configuration cases match the Rust fixture`);
}
