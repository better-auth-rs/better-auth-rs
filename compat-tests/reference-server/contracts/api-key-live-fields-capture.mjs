import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const createdAt = "2030-01-02T03:04:05.123Z";
const updatedAt = "2031-02-03T04:05:05.000Z";
const json = value => JSON.parse(JSON.stringify(value));
const fields = () => ({
  label: { type: "string", fieldName: "stored_label", required: false, defaultValue: "Default" },
  activatedAt: { type: "date", fieldName: "stored_activation", required: false },
  details: { type: "json", fieldName: "stored_details", required: false },
  revision: { type: "number", fieldName: "stored_revision", required: false, defaultValue: 1.5 },
});
const input = () => ({
  name: "Desk", start: null, prefix: null, key: "ordinary-stored-hash", referenceId: "ordinary-owner",
  configId: "default", refillInterval: 60000, refillAmount: 10, lastRefillAt: null, enabled: true,
  rateLimitEnabled: true, rateLimitTimeWindow: 60000, rateLimitMax: 3, requestCount: 0, remaining: 10,
  lastRequest: null, expiresAt: null, createdAt: new Date(createdAt), updatedAt: new Date(createdAt),
  permissions: null, metadata: null,
  activatedAt: "2029-01-02T03:04:05.000Z", details: { channel: "ordinary", enabled: true },
});

async function capture(backend, failOutput) {
  const memory = { user: [], session: [], account: [], verification: [], ordinary_api_key_fields: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = fields => ({
    database: sqlite ?? memoryAdapter(memory), baseURL: "http://api-key-fields.test",
    secret: "ordinary-api-key-extra-fields-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [apiKey(), { id: "ordinary-api-key-additional-fields", schema: { apikey: { modelName: "ordinary_api_key_fields", fields } } }],
  });
  try {
    if (sqlite) await (await getMigrations(options(fields()))).runMigrations();
    const raw = (await betterAuth(options(fields())).$context).adapter;
    const seed = await raw.create({ model: "apikey", data: input() });
    const writerFields = fields();
    writerFields.label.onUpdate = () => "Live";
    writerFields.revision.onUpdate = () => 2.5;
    const writer = (await betterAuth(options(writerFields)).$context).adapter;
    const events = [];
    const outputError = new Error("ordinary live API Key output error");
    const projection = {
      name: { type: "string", required: false, transform: { async output(value) {
        events.push(["name", value]);
        const row = await writer.update({ model: "apikey", where: [{ field: "id", value: seed.id }], update: { updatedAt: new Date(updatedAt) } });
        assert.equal(row.label, "Live");
        assert.equal(row.revision, 2.5);
        assert.equal(row.updatedAt.toISOString(), updatedAt);
        events.push(["write", { label: row.label, revision: row.revision, updatedAt: row.updatedAt.toISOString() }]);
        return `${value}:out`;
      } } },
      ...Object.fromEntries(Object.entries(fields()).map(([name, field]) => [name, { ...field, transform: { output(value) {
        events.push(["output", name, value === undefined ? { type: "undefined" } : json(value)]);
        if (name === "label" && failOutput) throw outputError;
        return name === "label" ? `${value}:out` : value;
      } } }])),
    };
    const reader = (await betterAuth(options(projection)).$context).adapter;
    let row = null;
    let error = null;
    try {
      row = await reader.findOne({ model: "apikey", where: [{ field: "id", value: seed.id }] });
    } catch (actual) {
      if (actual !== outputError) throw actual;
      error = { sameError: true, message: actual.message };
    }
    assert.equal(error !== null, failOutput);
    const stored = await raw.findOne({ model: "apikey", where: [{ field: "id", value: seed.id }] });
    const visible = row => {
      if (row === null) return null;
      assert.deepEqual(Object.keys(row).sort(), ["id", ...Object.keys(input()), "label", "revision"].sort());
      assert.equal(row.id, seed.id);
      assert.equal(row.createdAt.toISOString(), createdAt);
      const changed = row.updatedAt.toISOString();
      assert.ok([createdAt, updatedAt].includes(changed));
      return json({ ...row, id: "<api-key-id>", createdAt: "<created-at>", updatedAt: changed === createdAt ? "<created-at>" : changed });
    };
    assert.equal(stored.label, "Live");
    assert.equal(stored.revision, 2.5);
    assert.equal(stored.updatedAt.toISOString(), updatedAt);
    return { failOutput, events, result: visible(row), error, stored: visible(stored) };
  } finally {
    sqlite?.close();
  }
}

export async function captureApiKeyLiveFields() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) {
    const cases = [];
    for (const failOutput of [false, true]) cases.push(await capture(backend, failOutput));
    backends.push({ backend, cases });
  }
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureApiKeyLiveFields(), null, 2)}\n`);
}
