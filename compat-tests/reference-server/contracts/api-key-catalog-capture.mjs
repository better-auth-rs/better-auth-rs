import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { captureFreshServerCatalog, observeServerIndexes } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

const numbers = ["refillInterval", "refillAmount", "rateLimitTimeWindow", "rateLimitMax", "requestCount", "remaining"];
const strings = ["name", "start", "prefix", "permissions", "metadata"];
const date = new Date("2030-01-02T03:04:05.000Z");

async function storage({ options, query, backend }) {
  const { adapter } = await betterAuth(options).$context;
  const quote = name => backend === "mysql" ? `\`${name}\`` : `"${name}"`;
  const read = async id => {
    const row = await adapter.findOne({ model: "apikey", where: [{ field: "id", value: id }] });
    if (row === null) return null;
    return Object.fromEntries(["id", "key", "referenceId", "configId", "enabled", "rateLimitEnabled", ...numbers, ...strings]
      .map(field => [field, row[field]]));
  };
  const input = id => ({ id, key: "shared-native-key", referenceId: "owner-without-user-row", configId: "default",
    name: null, start: null, prefix: null, permissions: null, metadata: null,
    enabled: true, rateLimitEnabled: true, createdAt: date, updatedAt: date,
    ...Object.fromEntries(numbers.map(field => [field, null])), requestCount: 0 });
  const create = data => adapter.create({ model: "apikey", forceAllowId: true, data });
  const first = input("native-null-flags");
  await create(first);
  const placeholder = backend === "postgres" ? "$1" : "?";
  await query(`UPDATE ${quote("apikey")} SET ${["enabled", "rateLimitEnabled", ...numbers].map(field => `${quote(field)} = NULL`).join(", ")} WHERE ${quote("id")} = ${placeholder}`, [first.id]);
  const nullFlags = await read(first.id);
  const long = input("native-long-text");
  for (const field of strings) long[field] = `${field}:${"x".repeat(300)}`;
  await create(long);
  const longText = await read(long.id);
  const numeric = [];
  for (const [name, value] of [["integer", 7], ["fraction", 1.5], ["negative-fraction", -1.5], ["outside-int32", 2147483648]]) {
    const data = input(`native-number-${name}`);
    await create(data);
    let error = null;
    try {
      await adapter.update({ model: "apikey", where: [{ field: "id", value: data.id }],
        update: Object.fromEntries(numbers.map(field => [field, value])) });
    } catch (cause) {
      error = { name: cause.name, message: cause.message, code: cause.code ?? null };
    }
    numeric.push({ name, input: value, accepted: error === null, error, row: await read(data.id) });
  }
  return { nullFlags, longText, numeric };
}

export async function captureApiKeyCatalog(backend) {
  const config = { plugins: [apiKey()] };
  if (backend === "sqlite") {
    const database = new Database(":memory:");
    try {
      const options = { ...config, database, baseURL: "http://native-apikey.test",
        secret: "native-apikey-catalog-at-least-32-characters", logger: { disabled: true }, telemetry: { enabled: false } };
      await (await getMigrations(options)).runMigrations();
      const { catalog } = observeSqliteCatalog(database, "apikey", "The native API Key table must exist");
      return { columns: catalog.columns, constraints: { indexes: catalog.indexes, foreignKeys: catalog.foreignKeys },
        storage: await storage({ options, backend, query: async (sql, values) => database.query(sql).all(...values) }) };
    } finally {
      database.close();
    }
  }
  const captured = await captureFreshServerCatalog(backend, ["apikey"], config, async context => ({
    constraints: await observeServerIndexes(context, "apikey"), storage: await storage(context),
  }));
  return { columns: captured.columns, ...captured.observation };
}
