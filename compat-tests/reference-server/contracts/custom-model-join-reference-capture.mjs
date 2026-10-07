import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Database } from "bun:sqlite";
import { getAuthTables } from "@better-auth/core/db";
import { withSpan } from "@better-auth/core/instrumentation";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { observeValue } from "./device-where-capture.mjs";

const require = createRequire(new URL("../package.json", import.meta.url));
const { trace } = require("@opentelemetry/api");
const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

const date = new Date("2030-01-02T03:04:05.000Z");
const expiry = new Date("2032-01-02T03:04:05.000Z");
const tables = ["user", "session", "account", "verification", "badge"];
const scenarios = [
  { name: "native-relationship-control", declared: false },
  { name: "declared-badge-reference", declared: true, reference: "badge" },
  { name: "unknown-badge-reference", declared: false, reference: "badge", error: 'Model "badge" not found in schema' },
  { name: "native-unrelated-reference", declared: false, reference: "session" },
];
const operations = [
  { name: "user-control", surface: "adapter", relationship: "accounts", joined: false, missing: false },
  { name: "account-control", surface: "adapter", relationship: "owner", joined: false, missing: false },
  ...["adapter", "internal"].flatMap(surface => ["accounts", "owner"].flatMap(relationship => [true, false].map(missing => ({
    name: `${surface}-${relationship}-${missing ? "missing" : "existing"}`, surface, relationship, joined: true, missing,
  })))),
];

function optionsFor(scenario, joins, state) {
  const output = field => value => {
    if (state.enabled) state.events.push(["output", field, observeValue(value)]);
    return value;
  };
  return {
    baseURL: "http://custom-model-join-reference.test",
    secret: "custom-model-join-reference-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins } },
    user: { additionalFields: {
      name: { type: "string", required: true, transform: { output: output("user.name") } },
      image: { type: "string", required: false, transform: { output: output("user.image") } },
    } },
    account: { additionalFields: {
      accountId: { type: "string", required: true, transform: { output: output("account.accountId") } },
      userId: { type: "string", required: true, index: true, references: { model: "user", field: "id", onDelete: "cascade" },
        transform: { output: output("account.userId") } },
      badgeId: { type: "string", required: false,
        ...(scenario.reference ? { references: { model: scenario.reference, field: "id" } } : {}),
        transform: { output: output("account.badgeId") } },
    } },
    plugins: scenario.declared ? [{ id: "custom-model-join-reference", schema: { badge: { fields: {
      label: { type: "string", required: true, transform: { output: output("badge.label") } },
    } } } }] : [],
  };
}

function rows() {
  return {
    user: ["a", "b"].map(suffix => ({
      name: `User ${suffix}`, email: `${suffix}@custom-model-join-reference.test`, emailVerified: true,
      image: `image-${suffix}`, createdAt: date, updatedAt: date, id: `user-${suffix}`,
    })),
    badge: [{ label: "Stored badge", id: "badge-a" }],
    account: ["a", "b"].map(suffix => ({
      accountId: `external-${suffix}`, providerId: "provider", userId: `user-${suffix}`,
      accessToken: `access-${suffix}`, refreshToken: `refresh-${suffix}`, idToken: `identity-${suffix}`,
      accessTokenExpiresAt: expiry, refreshTokenExpiresAt: expiry, scope: "read", password: `hash-${suffix}`,
      createdAt: date, updatedAt: date, badgeId: "badge-a", id: `account-${suffix}`,
    })),
  };
}

function keyOrder(value, path = []) {
  if (value === null || typeof value !== "object" || value instanceof Date) return [];
  return [{ path, keys: Object.keys(value) }, ...Object.entries(value).flatMap(([key, child]) => keyOrder(child, [...path, key]))];
}

function errorValue(error) {
  assert.ok(error instanceof Error);
  return {
    name: error.name, message: error.message,
    properties: observeValue(Object.fromEntries(Object.entries(error))), keys: Object.keys(error),
  };
}

function rawError(error) {
  return { ...errorValue(error), ownProperties: observeValue(Object.fromEntries(
    Object.getOwnPropertyNames(error).map(name => [name, error[name]]),
  )) };
}

async function outcome(action, diagnostics, context) {
  try {
    const result = await action();
    return { returned: true, result: observeValue(result), json: JSON.parse(JSON.stringify(result)), keyOrder: keyOrder(result) };
  } catch (error) {
    diagnostics.push({ ...context, error: rawError(error) });
    if (error instanceof assert.AssertionError) throw error;
    return { returned: false, error: errorValue(error) };
  }
}

async function invoke(context, operation, seed) {
  const userId = operation.missing ? "missing-user" : seed.user[0].id;
  const accountId = operation.missing ? "missing-account" : seed.account[0].id;
  if (operation.surface === "internal") {
    return operation.relationship === "accounts"
      ? context.internalAdapter.findUserByEmail(operation.missing ? "missing@custom-model-join-reference.test" : seed.user[0].email, { includeAccounts: true })
      : context.internalAdapter.findAccountOwnerByKey({ providerId: "provider", accountId: operation.missing ? "missing-external" : seed.account[0].accountId });
  }
  const accounts = operation.relationship === "accounts";
  return context.adapter.findOne({
    model: accounts ? "user" : "account", where: [{ field: "id", value: accounts ? userId : accountId }],
    ...(operation.joined ? { join: accounts ? { account: true } : { user: true } } : {}),
  });
}

function assertOperation(scenario, joins, operation, observed, events, seed) {
  if (operation.joined && scenario.error) {
    assert.deepEqual(observed, { returned: false, error: {
      name: "BetterAuthError", message: scenario.error, properties: { name: "BetterAuthError" }, keys: ["name"],
    } });
    assert.deepEqual(events, [], "Unknown references must fail before every raw query and output callback");
    return;
  }
  const accounts = operation.relationship === "accounts";
  const user = seed.user[0];
  const account = seed.account[0];
  const expected = operation.missing ? null : !operation.joined ? (accounts ? user : account)
    : operation.surface === "internal" ? (accounts ? { user, accounts: [account] } : { kind: "owned", user, account })
      : accounts ? { ...user, account: [account] } : { ...account, user };
  assert.deepEqual(observed, {
    returned: true, result: observeValue(expected), json: JSON.parse(JSON.stringify(expected)), keyOrder: keyOrder(expected),
  });
  const expectedEvents = [["query", operation.surface === "internal" && !accounts ? "findMany" : "findOne", accounts ? "user" : "account"]];
  if (!operation.missing) {
    const userEvents = ["name", "image"].map(field => ["output", `user.${field}`, user[field]]);
    const accountEvents = ["accountId", "userId", "badgeId"].map(field => ["output", `account.${field}`, account[field]]);
    expectedEvents.push(...(accounts ? userEvents : accountEvents));
    if (operation.joined) {
      if (!joins) expectedEvents.push(["query", accounts ? "findMany" : "findOne", accounts ? "account" : "user"]);
      expectedEvents.push(...(accounts ? accountEvents : userEvents));
    }
  }
  assert.deepEqual(events, expectedEvents, "Compare every query and callback; the unrelated model must not be read");
}

async function runtime(backend, scenario, joins, recorder, diagnostics) {
  const state = { enabled: false, events: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const database = sqlite ?? memoryAdapter(memory);
  const seed = rows();
  const baseline = { ...optionsFor({ declared: true }, joins, state), database };
  const stored = () => Object.fromEntries(tables.map(model => [model, observeValue(sqlite
    ? sqlite.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model]) ]));
  try {
    // A physical table does not register a model in the runtime schema.
    if (sqlite) await (await getMigrations(baseline)).runMigrations();
    const writer = (await betterAuth(baseline).$context).adapter;
    for (const model of ["user", "badge", "account"]) for (const data of seed[model]) {
      await writer.create({ model, forceAllowId: true, data });
    }
    const before = stored();
    const captured = [];
    const options = { ...optionsFor(scenario, joins, state), database };
    const registeredModels = Object.keys(getAuthTables(options));
    assert.deepEqual(registeredModels, scenario.declared ? tables : tables.slice(0, -1));
    for (const operation of operations) {
      const context = await betterAuth(options).$context;
      state.events = [];
      state.enabled = true;
      recorder.events = state.events;
      let observed;
      try {
        observed = await outcome(() => invoke(context, operation, seed), diagnostics, {
          backend, scenario: scenario.name, joins, operation: operation.name,
        });
      } finally { state.enabled = false; recorder.events = null; }
      const after = stored();
      try {
        assert.deepEqual(after, before, "Every control, joined read, and reference error must preserve all stored tables");
        assertOperation(scenario, joins, operation, observed, state.events, seed);
      } catch (error) {
        diagnostics.push({ backend, scenario: scenario.name, joins, operation, before, events: state.events,
          observed, after, assertion: rawError(error) });
        throw error;
      }
      captured.push({ ...operation, events: state.events, ...observed, storageUnchanged: true });
    }
    return { backend, scenario: scenario.name, joins, registeredModels, before, operations: captured, after: stored() };
  } finally { state.enabled = false; recorder.events = null; sqlite?.close(); }
}

export async function captureCustomModelJoinReferences({ diagnostics = [] } = {}) {
  const recorder = { events: null };
  let warmup = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return {
    startActiveSpan(name, options, callback) {
      if (name === "custom-model-join-reference-warmup") warmup = true;
      const attributes = options.attributes;
      if (attributes["db.operation.name"] && attributes["db.collection.name"]) {
        recorder.events?.push(["query", attributes["db.operation.name"], attributes["db.collection.name"]]);
      }
      return callback({ end() {}, setAttribute() {}, setStatus() {}, recordException() {} });
    },
  }; } }), true);
  try {
    for (let attempt = 0; attempt < 50 && !warmup; attempt++) {
      await withSpan("custom-model-join-reference-warmup", {}, async () => {});
      if (!warmup) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(warmup, true, "The query recorder must be active before sampling");
    const cases = [];
    for (const scenario of scenarios) for (const backend of ["memory", "sqlite"]) for (const joins of [false, true]) {
      cases.push(await runtime(backend, scenario, joins, recorder, diagnostics));
    }
    assert.equal(cases.length, 16);
    assert.equal(cases.reduce((total, value) => total + value.operations.length, 0), 160);
    return { version, scenarios, cases };
  } finally { trace.disable(); }
}

if (import.meta.main) {
  const diagnostics = [];
  try {
    const serialized = `${JSON.stringify(await captureCustomModelJoinReferences({ diagnostics }), null, 2)}\n`;
    if (process.argv[2]) writeFileSync(process.argv[2], serialized);
    else process.stdout.write(serialized);
  } finally {
    // Keep host-dependent stacks outside the deterministic fixture without discarding diagnostics.
    if (process.argv[2]) writeFileSync(`${process.argv[2]}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
