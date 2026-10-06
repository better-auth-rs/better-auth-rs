import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Database } from "bun:sqlite";
import { createAdapterFactory } from "@better-auth/core/db/adapter";
import { withSpan } from "@better-auth/core/instrumentation";
import { createKyselyAdapter, kyselyAdapter } from "@better-auth/kysely-adapter";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { observeSchemaJoinReferenceBoundary } from "./schema-join-reference-conflict-capture.mjs";

const require = createRequire(new URL("../package.json", import.meta.url));
const { trace } = require("@opentelemetry/api");
const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const date = new Date("2030-01-02T03:04:05.000Z");
const row = { id: "owner", name: "Owner", email: "owner@join-history.test", emailVerified: true, image: "account", createdAt: date, updatedAt: date };
const rollback = new Error("join-history-rollback");
const sequences = [
  { name: "repeated-owner", mode: "duplicate", steps: ["owner", "owner", "accounts", "owner"] },
  { name: "reversed-order", mode: "duplicate", steps: ["accounts", "owner", "accounts", "owner"] },
  { name: "ordinary-missing-read", mode: "duplicate", steps: ["owner", "read-user", "owner"] },
  { name: "empty-where-null-read", mode: "duplicate", steps: ["owner", "read-user-empty", "owner"] },
  { name: "unknown-where-field", mode: "duplicate", steps: ["owner", "read-user-invalid", "owner"] },
  { name: "failed-join-warmup", mode: "invalid-target", steps: ["owner", "accounts", "owner"] },
  { name: "primary-id-alias", mode: "alias", steps: ["owner", "owner", "read-user", "owner"] },
];
const boundarySequences = [
  { name: "input-callback-failure", mode: "duplicate", steps: ["owner", "create-user-fail", "owner"] },
  { name: "output-without-where", mode: "duplicate", steps: ["owner", "read-user-output", "owner"] },
  { name: "output-callback-failure", mode: "duplicate", steps: ["owner", "read-user-output-fail", "owner"] },
];

function optionsFor(mode, joins, record) {
  const output = field => value => {
    record.events?.push(["output", field, value]);
    if (record.operation === "read-user-output-fail" && field === "user.name") throw new Error("history-output-failure");
    return value;
  };
  const userFields = {
    id: { type: "string", ...(mode === "alias" ? { fieldName: "stored_id" } : { references: { model: "account", field: "id" } }), transform: { output: output("user.id") } },
    name: { type: "string", transform: {
      input: value => {
        record.events?.push(["input", "user.name", value]);
        if (record.operation === "create-user-fail") throw new Error("history-input-failure");
        return value;
      },
      output: output("user.name"),
    } },
    ...(mode === "alias" ? {} : { image: { type: "string", references: { model: "account", field: "id" }, transform: { output: output("user.image") } } }),
  };
  return {
    baseURL: "http://join-history.test",
    secret: "join-history-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins } },
    user: { additionalFields: userFields },
    account: { additionalFields: {
      accountId: { type: "string", transform: { output: output("account.accountId") } },
      ...(mode === "invalid-target" ? { userId: { type: "string", references: { model: "user", field: "missingUserField" } } } : {}),
    } },
  };
}

function execute(adapter, operation) {
  switch (operation) {
    case "accounts": return adapter.findOne({ model: "user", where: [{ field: "id", value: "owner" }], join: { account: true } });
    case "owner": return adapter.findOne({ model: "account", where: [{ field: "id", value: "account" }], join: { user: true } });
    case "read-user": return adapter.findOne({ model: "user", where: [{ field: "name", value: "missing" }] });
    case "read-user-invalid": return adapter.findOne({ model: "user", where: [{ field: "missingUserField", value: "missing" }] });
    case "create-user-fail": return adapter.create({ model: "user", data: { ...row }, forceAllowId: true });
    case "read-user-empty":
    case "read-user-output":
    case "read-user-output-fail": return adapter.findOne({ model: "user", where: [] });
    default: throw new Error(`Unknown history operation: ${operation}`);
  }
}

async function step(adapter, operation, record, scope = "parent") {
  const events = [];
  record.events = events;
  record.operation = operation;
  try {
    let result;
    try { result = await execute(adapter, operation); }
    catch (error) { result = { error: error.message }; }
    return { scope, operation, events, result };
  } finally { record.events = null; record.operation = null; }
}

async function openAdapter(backend, options, record, transaction = true) {
  if (backend === "boundary") {
    const fresh = () => createAdapterFactory({
      config: { adapterId: "schema-reference-history", supportsJSON: true },
      adapter: () => ({
        async findOne(input) {
          record.events.push(["findOne", input]);
          return record.operation?.startsWith("read-user-output") ? { ...row } : null;
        },
      }),
    })(options);
    return { fresh, close: async () => {} };
  }
  if (backend === "memory") {
    const data = { user: [], account: [], session: [], verification: [] };
    return { fresh: () => memoryAdapter(data)(options), close: async () => {} };
  }
  const sqlite = new Database(":memory:");
  let kysely;
  try {
    // Keep physical tables canonical so runtime metadata changes remain observable.
    await (await getMigrations({ ...options, user: undefined, account: undefined, database: sqlite })).runMigrations();
    ({ kysely } = await createKyselyAdapter({ database: sqlite }));
    return {
      fresh: () => kyselyAdapter(kysely, { type: "sqlite", transaction })(options),
      close: () => kysely.destroy(),
    };
  } catch (error) {
    if (kysely) await kysely.destroy();
    else sqlite.close();
    throw error;
  }
}

async function captureSequence(backend, joins, sequence, record) {
  const options = optionsFor(sequence.mode, joins, record);
  const resource = await openAdapter(backend, options, record);
  try {
    const adapter = resource.fresh();
    const observations = [];
    for (const operation of sequence.steps) observations.push(await step(adapter, operation, record));
    observations.push(await step(resource.fresh(), "owner", record, "fresh"));
    if (backend === "boundary") {
      const events = [];
      const result = await observeSchemaJoinReferenceBoundary(options, "owner", events);
      observations.push({ scope: "existing-fresh-control", operation: "owner", events, result });
    }
    return { backend, joins, name: sequence.name, mode: sequence.mode, observations };
  } finally { await resource.close(); }
}

async function captureTransaction(backend, joins, transaction, warmParent, finish, record) {
  const resource = await openAdapter(backend, optionsFor("duplicate", joins, record), record, transaction);
  try {
    const adapter = resource.fresh();
    const observations = [await step(adapter, "owner", record)];
    if (warmParent) {
      observations.push(await step(adapter, "read-user", record));
      observations.push(await step(adapter, "owner", record));
    }
    async function transact(current, scope, nested) {
      try {
        const result = await current.transaction(async active => {
          observations.push(await step(active, "owner", record, scope));
          if (nested) {
            await transact(active, "nested", false);
            observations.push(await step(active, "owner", record, scope));
          }
          observations.push(await step(active, "read-user", record, scope));
          observations.push(await step(active, "owner", record, scope));
          if (finish === "rollback") throw rollback;
          return "committed";
        });
        observations.push({ scope, operation: "transaction-result", result });
      } catch (error) {
        if (error !== rollback) throw error;
        observations.push({ scope, operation: "transaction-result", result: { error: error.message } });
      }
    }
    await transact(adapter, "transaction", true);
    observations.push(await step(adapter, "owner", record));
    observations.push(await step(resource.fresh(), "owner", record, "fresh"));
    return { backend, joins, transaction, warmParent, finish, observations };
  } finally { await resource.close(); }
}

export async function captureSchemaJoinReferenceHistory() {
  const record = { events: null, operation: null };
  let warmup = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return {
    startActiveSpan(name, options, callback) {
      if (name === "schema-join-history-warmup") warmup = true;
      const attributes = options.attributes;
      if (attributes["db.operation.name"] && attributes["db.collection.name"]) {
        record.events?.push(["query", attributes["db.operation.name"], attributes["db.collection.name"]]);
      }
      return callback({ end() {}, setAttribute() {}, setStatus() {}, recordException() {} });
    },
  }; } }), true);
  try {
    // The upstream instrumentation loads the OpenTelemetry API asynchronously.
    for (let attempt = 0; attempt < 50 && !warmup; attempt++) {
      await withSpan("schema-join-history-warmup", {}, async () => {});
      if (!warmup) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(warmup, true, "The query recorder must be active before sampling");
    const cases = [];
    for (const backend of ["boundary", "memory", "sqlite"]) for (const joins of [false, true]) {
      for (const sequence of sequences) cases.push(await captureSequence(backend, joins, sequence, record));
      if (backend === "boundary") for (const sequence of boundarySequences) {
        cases.push(await captureSequence(backend, joins, sequence, record));
      }
    }
    const transactions = [];
    for (const backend of ["boundary", "memory", "sqlite"]) for (const joins of [false, true]) {
      for (const transaction of backend === "sqlite" ? [false, true] : [backend === "memory"]) {
        for (const warmParent of [false, true]) for (const finish of ["commit", "rollback"]) {
          transactions.push(await captureTransaction(backend, joins, transaction, warmParent, finish, record));
        }
      }
    }
    return { version, cases, transactions };
  } finally { trace.disable(); }
}

if (import.meta.main) {
  // Preserve absent JavaScript values instead of dropping raw adapter arguments.
  const serialized = `${JSON.stringify(await captureSchemaJoinReferenceHistory(), (_, value) => value === undefined ? { $undefined: true } : value, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
