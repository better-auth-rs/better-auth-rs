import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { withSpan } from "@better-auth/core/instrumentation";

const require = createRequire(new URL("../package.json", import.meta.url));
const { trace } = require("@opentelemetry/api");
const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const email = "owner@schema-join-reference.test";
const modes = ["default", "removed", "account-duplicate", "user-duplicate"];

async function observe(backend, joins, mode, populated, operation, record, tables) {
  const memory = { user: [], session: [], account: [], verification: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = {
    database: sqlite ?? memoryAdapter(memory),
    baseURL: "http://schema-join-reference.test",
    secret: "schema-join-reference-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins } },
    ...(tables ? { user: { modelName: tables.user }, account: { modelName: tables.account } } : {}),
  };
  const events = [];
  const output = field => value => { record()?.push(["output", field, value]); return value; };
  const userFields = {
    name: { type: "string", required: true, transform: { output: output("user.name") } },
  };
  const accountFields = {
    accountId: { type: "string", required: true, transform: { output: output("account.accountId") } },
  };
  if (mode === "removed") accountFields.userId = { type: "string", required: true };
  if (tables) accountFields.userId = {
    type: "string", required: true, references: { model: tables.user, field: "id" },
  };
  if (mode === "account-duplicate" || mode === "account-mixed-duplicate") accountFields.accessToken = {
    type: "string", required: false, references: { model: "user", field: "id" },
  };
  if (mode === "user-duplicate" || mode === "user-mixed-duplicate") {
    userFields.name.references = { model: "account", field: "id" };
    userFields.image = { type: "string", required: false, references: { model: tables?.account ?? "account", field: "id" } };
  }
  try {
    // Native field replacements change runtime metadata without changing the common physical tables.
    if (sqlite) await (await getMigrations(options)).runMigrations();
    const reader = (await betterAuth(options).$context).adapter;
    if (populated) {
      const date = new Date("2030-01-02T03:04:05.000Z");
      await reader.create({ model: "user", forceAllowId: true, data: {
        id: "owner", name: "Owner", email, emailVerified: true, image: "owner-image",
        createdAt: date, updatedAt: date,
      } });
      await reader.create({ model: "account", forceAllowId: true, data: {
        id: "account", userId: "owner", accountId: "external-owner", providerId: "provider",
        accessToken: "original-access", createdAt: date, updatedAt: date,
      } });
    }
    const context = await betterAuth({ ...options,
      user: { ...options.user, additionalFields: userFields }, account: { ...options.account, additionalFields: accountFields },
    }).$context;
    record(events);
    let result;
    try {
      if (operation === "accounts") {
        const joined = await context.internalAdapter.findUserByEmail(email, { includeAccounts: true });
        result = joined === null ? null : { user: userSummary(joined.user), accounts: joined.accounts.map(accountSummary) };
      } else {
        const joined = await context.internalAdapter.findAccountOwnerByKey({ providerId: "provider", accountId: "external-owner" });
        result = joined === null ? null : { account: accountSummary(joined.account), user: joined.kind === "owned" ? userSummary(joined.user) : null };
      }
    } catch (error) {
      result = { error: error.message };
    } finally { record(null); }
    const invalid = mode === "removed" || mode === "account-duplicate" || mode === "account-mixed-duplicate"
      || ((mode === "user-duplicate" || mode === "user-mixed-duplicate") && operation === "owner");
    if (invalid) {
      assert.equal(typeof result?.error, "string");
      assert.deepEqual(events, [], "Reference errors must precede raw reads and output callbacks");
    } else {
      assert.equal(result?.error, undefined);
      assert.equal(result === null, !populated);
      assert.ok(events.some(event => event[0] === "query"), "The successful control must execute a raw read");
    }
    return { backend, joins, mode, populated, operation, ...(tables ? { tables } : {}), events, result };
  } finally { record(null); sqlite?.close(); }
}

function userSummary(user) {
  return { id: user.id, name: user.name, image: user.image };
}
function accountSummary(account) {
  return { id: account.id, accountId: account.accountId, userId: account.userId, accessToken: account.accessToken };
}

export async function captureSchemaJoinReferences({ aliases = false } = {}) {
  let events;
  let warmup = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return {
    startActiveSpan(name, options, callback) {
      if (name === "schema-join-warmup") warmup = true;
      const attributes = options.attributes;
      if (attributes["db.operation.name"] && attributes["db.collection.name"]) {
        events?.push(["query", attributes["db.operation.name"], attributes["db.collection.name"]]);
      }
      return callback({ end() {}, setAttribute() {}, setStatus() {}, recordException() {} });
    },
  }; } }), true);
  try {
    // The upstream instrumentation loads the OpenTelemetry API asynchronously.
    for (let attempt = 0; attempt < 50 && !warmup; attempt++) {
      await withSpan("schema-join-warmup", {}, async () => {});
      if (!warmup) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(warmup, true, "The query recorder must be active before sampling");
    const record = (...value) => {
      if (value.length) events = value[0];
      return events;
    };
    const cases = [];
    const tableCases = aliases ? [{ user: "users", account: "accounts" }, { user: "users", account: "native_accounts" }] : [undefined];
    for (const tables of tableCases) for (const backend of aliases ? ["sqlite"] : ["memory", "sqlite"]) for (const joins of [false, true]) {
      for (const mode of aliases ? ["alias", "account-mixed-duplicate", "user-mixed-duplicate"] : modes) for (const populated of [false, true]) {
        for (const operation of ["accounts", "owner"]) {
          cases.push(await observe(backend, joins, mode, populated, operation, record, tables));
        }
      }
    }
    return { version, cases };
  } finally { trace.disable(); }
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureSchemaJoinReferences(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
