import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Database } from "bun:sqlite";
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
const expiry = new Date("2100-01-02T03:04:05.000Z");
const token = "session-user-join-existing-token";
const missingToken = "session-user-join-missing-token";
const tables = ["user", "session", "account", "verification"];
const reference = { references: { model: "user", field: "id" } };
const scenarios = [
  { name: "default" },
  {
    name: "removed-reference", sessionFields: { userId: { required: true, index: true } },
    error: "No foreign key found for model user and base model session while performing join operation.",
  },
  {
    name: "second-optional-user-reference", sessionFields: { ownerRef: reference },
    error: "Multiple foreign keys found for model user and base model session while performing join operation. Only one foreign key is supported.",
  },
];
const operations = [
  { name: "session-control", surface: "adapter", input: { model: "session", where: [{ field: "token", value: token }] } },
  { name: "user-control", surface: "adapter", input: { model: "user", where: [{ field: "id", value: "user-a" }] } },
  ...[missingToken, token].flatMap(value => [
    { name: value === token ? "adapter-existing" : "adapter-missing", surface: "adapter", joined: true,
      input: { model: "session", where: [{ field: "token", value }], join: { user: true } } },
    { name: value === token ? "internal-existing" : "internal-missing", surface: "internal", joined: true, token: value },
  ]),
];

function optionsFor(scenario, joins, state) {
  const fields = (model, declarations) => Object.fromEntries(Object.entries(declarations).map(([name, declaration]) => [name, {
    type: "string", required: false, ...declaration,
    transform: { output(value) {
      if (state.enabled) state.events.push(["output", `${model}.${name}`, observeValue(value)]);
      return value;
    } },
  }]));
  return {
    baseURL: "http://session-user-join-reference.test",
    secret: "session-user-join-reference-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins } },
    user: { additionalFields: fields("user", { name: { required: true }, image: {} }) },
    session: { additionalFields: fields("session", {
      token: { required: true, unique: true },
      userId: { required: true, index: true, references: { ...reference.references, onDelete: "cascade" } },
      ownerRef: {}, ...scenario.sessionFields,
    }) },
  };
}

function rows() {
  return {
    user: ["a", "b"].map(suffix => ({
      name: `User ${suffix}`, email: `${suffix}@session-user-join-reference.test`, emailVerified: true,
      image: `image-${suffix}`, createdAt: date, updatedAt: date, id: `user-${suffix}`,
    })),
    session: [{
      expiresAt: expiry, token, createdAt: date, updatedAt: date,
      ipAddress: "203.0.113.8", userAgent: "session-user-join-reference", userId: "user-a",
      ownerRef: "user-b", id: "session-a",
    }],
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

function assertOperation(scenario, joins, operation, observed, events, seed) {
  if (operation.joined && scenario.error) {
    assert.deepEqual(observed, { returned: false, error: {
      name: "BetterAuthError", message: scenario.error, properties: { name: "BetterAuthError" }, keys: ["name"],
    } });
    assert.deepEqual(events, [], "Join reference errors must precede every raw query and output callback");
    return;
  }
  const userControl = operation.name === "user-control";
  const missing = operation.name.endsWith("missing");
  const expected = missing ? null : userControl ? seed.user[0] : !operation.joined ? seed.session[0]
    : operation.surface === "internal" ? { session: seed.session[0], user: seed.user[0] }
      : { ...seed.session[0], user: seed.user[0] };
  assert.deepEqual(observed, {
    returned: true, result: observeValue(expected), json: JSON.parse(JSON.stringify(expected)), keyOrder: keyOrder(expected),
  });
  const expectedEvents = [["query", "findOne", userControl ? "user" : "session"]];
  if (!missing) {
    if (!userControl) expectedEvents.push(...["token", "userId", "ownerRef"].map(name => ["output", `session.${name}`, seed.session[0][name]]));
    if (operation.joined && !joins) expectedEvents.push(["query", "findOne", "user"]);
    if (userControl || operation.joined) expectedEvents.push(...["name", "image"].map(name => ["output", `user.${name}`, seed.user[0][name]]));
  }
  assert.deepEqual(events, expectedEvents, "Compare every query and original callback value in operation order");
}

async function runtime(backend, scenario, joins, recorder, diagnostics) {
  const state = { enabled: false, events: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const database = sqlite ?? memoryAdapter(memory);
  const seed = rows();
  const baseline = { ...optionsFor(scenarios[0], joins, state), database };
  const stored = () => Object.fromEntries(tables.map(model => [model, observeValue(sqlite
    ? sqlite.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model]) ]));
  try {
    // Replacing runtime references must not change the physical catalog or seeded controls.
    if (sqlite) await (await getMigrations(baseline)).runMigrations();
    const writer = (await betterAuth(baseline).$context).adapter;
    for (const model of ["user", "session"]) for (const data of seed[model]) {
      await writer.create({ model, forceAllowId: true, data });
    }
    const before = stored();
    const captured = [];
    for (const operation of operations) {
      const context = await betterAuth({ ...optionsFor(scenario, joins, state), database }).$context;
      state.events = [];
      state.enabled = true;
      recorder.events = state.events;
      let observed;
      try {
        observed = await outcome(() => operation.surface === "internal"
          ? context.internalAdapter.findSession(operation.token)
          : context.adapter.findOne(structuredClone(operation.input)), diagnostics, {
          backend, scenario: scenario.name, joins, operation: operation.name,
        });
      } finally { state.enabled = false; recorder.events = null; }
      const after = stored();
      try {
        assert.deepEqual(after, before, "Every successful read and reference error must preserve all stored tables");
        assertOperation(scenario, joins, operation, observed, state.events, seed);
      } catch (error) {
        diagnostics.push({ backend, scenario: scenario.name, joins, operation, before, events: state.events,
          observed, after, assertion: rawError(error) });
        throw error;
      }
      captured.push({ ...operation, events: state.events, ...observed, storageUnchanged: true });
    }
    return { backend, scenario: scenario.name, joins, before, operations: captured, after: stored() };
  } finally { state.enabled = false; recorder.events = null; sqlite?.close(); }
}

export async function captureSessionUserJoinReferences({ diagnostics = [] } = {}) {
  const recorder = { events: null };
  let warmup = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return {
    startActiveSpan(name, options, callback) {
      if (name === "session-user-join-reference-warmup") warmup = true;
      const attributes = options.attributes;
      if (attributes["db.operation.name"] && attributes["db.collection.name"]) {
        recorder.events?.push(["query", attributes["db.operation.name"], attributes["db.collection.name"]]);
      }
      return callback({ end() {}, setAttribute() {}, setStatus() {}, recordException() {} });
    },
  }; } }), true);
  try {
    for (let attempt = 0; attempt < 50 && !warmup; attempt++) {
      await withSpan("session-user-join-reference-warmup", {}, async () => {});
      if (!warmup) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(warmup, true, "The query recorder must be active before sampling");
    const cases = [];
    for (const scenario of scenarios) for (const backend of ["memory", "sqlite"]) for (const joins of [false, true]) {
      cases.push(await runtime(backend, scenario, joins, recorder, diagnostics));
    }
    assert.equal(cases.length, 12);
    assert.equal(cases.reduce((total, value) => total + value.operations.length, 0), 72);
    return { version, scenarios, cases };
  } finally { trace.disable(); }
}

if (import.meta.main) {
  const diagnostics = [];
  try {
    const serialized = `${JSON.stringify(await captureSessionUserJoinReferences({ diagnostics }), null, 2)}\n`;
    if (process.argv[2]) writeFileSync(process.argv[2], serialized);
    else process.stdout.write(serialized);
  } finally {
    // Keep host-dependent stacks outside the deterministic fixture without discarding diagnostics.
    if (process.argv[2]) writeFileSync(`${process.argv[2]}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
