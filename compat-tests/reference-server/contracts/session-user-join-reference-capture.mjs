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
const selectedScenarios = [
  {
    name: "alternate-session-reference",
    sessionFields: { userId: { required: true, index: true }, ownerRef: reference },
  },
  {
    name: "session-output-selects-fallback-owner",
    sessionFields: { userId: { required: true, index: true }, ownerRef: reference },
    replacements: { "session.ownerRef": ["user-b", "user-c"] },
  },
  {
    name: "reverse-user-reference-many", reverse: true, many: true,
    userFields: { image: { references: { model: "session", field: "id" } } },
  },
  {
    name: "reverse-user-reference-many-limit", reverse: true, many: true, limit: 1,
    userFields: { image: { references: { model: "session", field: "id" } } },
  },
  {
    name: "reverse-user-reference-many-empty", reverse: true, many: true, missingChild: true,
    userFields: { image: { references: { model: "session", field: "id" } } },
  },
  {
    name: "reverse-user-reference-unique", reverse: true,
    userFields: { image: { references: { model: "session", field: "id" }, unique: true } },
  },
  {
    name: "reverse-user-reference-unique-missing", reverse: true, missingChild: true,
    userFields: { image: { references: { model: "session", field: "id" }, unique: true } },
  },
];
const secondToken = `${token}-b`;
const batchTokens = [secondToken, missingToken, token];
const selectedOperations = [
  { name: "adapter-find-one", surface: "adapter", joined: true,
    input: { model: "session", where: [{ field: "token", value: token }], join: { user: true } } },
  { name: "internal-find-session", surface: "internal", joined: true, token },
  { name: "adapter-find-many", surface: "adapter", joined: true, batch: true,
    input: { model: "session", where: [{ field: "token", value: batchTokens, operator: "in" }], join: { user: true } } },
  { name: "internal-find-sessions", surface: "internal", joined: true, batch: true, tokens: batchTokens },
];

function replace(scenario, model, field, value) {
  const replacement = scenario.replacements?.[`${model}.${field}`];
  return replacement && value === replacement[0] ? replacement[1] : value;
}

function optionsFor(scenario, joins, state) {
  const fields = (model, declarations) => Object.fromEntries(Object.entries(declarations).map(([name, declaration]) => [name, {
    type: "string", required: false, ...declaration,
    transform: { output(value) {
      if (state.enabled) state.events.push(["output", `${model}.${name}`, observeValue(value)]);
      return replace(scenario, model, name, value);
    } },
  }]));
  return {
    baseURL: "http://session-user-join-reference.test",
    secret: "session-user-join-reference-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins, ...(scenario.limit === undefined ? {} : { defaultFindManyLimit: scenario.limit }) } },
    user: { additionalFields: fields("user", { name: { required: true }, image: {}, ...scenario.userFields }) },
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

function selectedRows(scenario) {
  return {
    user: ["a", "b", "c"].map(suffix => ({
      name: `User ${suffix}`, email: `${suffix}@session-user-join-reference.test`, emailVerified: true,
      image: !scenario.reverse ? `image-${suffix}` : suffix === "a" ? "session-b"
        : !scenario.missingChild && (suffix === "b" || scenario.many) ? "session-a" : null,
      createdAt: date, updatedAt: date, id: `user-${suffix}`,
    })),
    session: ["a", "b"].map(suffix => ({
      expiresAt: expiry, token: suffix === "a" ? token : secondToken, createdAt: date, updatedAt: date,
      ipAddress: "203.0.113.8", userAgent: "session-user-join-reference", userId: `user-${suffix}`,
      ownerRef: suffix === "a" ? "user-b" : "user-a", id: `session-${suffix}`,
    })),
  };
}

function selectedRelation(scenario, joins, operation, seed) {
  const tokens = operation.batch ? batchTokens : [token];
  const parents = seed.session.filter(row => tokens.includes(row.token)).slice(0, operation.batch ? scenario.limit ?? 100 : 1);
  const children = parents.map(parent => {
    const value = scenario.reverse ? parent.id
      : joins ? parent.ownerRef : replace(scenario, "session", "ownerRef", parent.ownerRef);
    const matches = seed.user.filter(user => (scenario.reverse ? user.image : user.id) === value);
    if (!scenario.many) assert.ok(matches.length <= 1, "A unique relation must have at most one matching User");
    return matches.slice(0, scenario.many ? scenario.limit ?? 100 : 1);
  });
  return { parents, children };
}

function selectedResult(scenario, operation, relation) {
  const project = (model, row) => Object.fromEntries(Object.entries(row)
    .map(([name, value]) => [name, replace(scenario, model, name, value)]));
  const joined = relation.parents.map((parent, index) => {
    const users = relation.children[index].map(user => project("user", user));
    return { ...project("session", parent), user: scenario.many ? users : users[0] ?? null };
  });
  if (operation.surface === "adapter") return operation.batch ? joined : joined[0] ?? null;
  if (operation.batch) {
    if (joined.some(row => row.user === null)) return [];
    return joined.map(({ user, ...session }) => ({ session, user }));
  }
  const row = joined[0];
  if (!row || row.user === null) return null;
  const { user, ...session } = row;
  // Single lookup converts a User array to an object; batch lookup preserves the array.
  return { session, user: { ...user } };
}

function selectedEvents(backend, scenario, joins, operation, relation) {
  const { parents, children } = relation;
  const event = (model, row, field) => ["output", `${model}.${field}`, observeValue(row[field])];
  const events = [["query", operation.batch ? "findMany" : "findOne", "session"]];
  for (const field of ["token", "userId", "ownerRef"]) for (const parent of parents) {
    events.push(event("session", parent, field));
  }
  if (!joins) for (const _ of parents) events.push(["query", scenario.many ? "findMany" : "findOne", "user"]);
  // For this two-child seed, SQLite fallback finishes the first child group before projecting the second group.
  if (backend === "sqlite" && !joins) {
    for (const users of children) for (const user of users) for (const field of ["name", "image"]) {
      events.push(event("user", user, field));
    }
  } else {
    const childCount = Math.max(0, ...children.map(users => users.length));
    for (let index = 0; index < childCount; index++) for (const field of ["name", "image"]) for (const users of children) {
      if (users[index]) events.push(event("user", users[index], field));
    }
  }
  return events;
}

function assertSelectedOperation(backend, scenario, joins, operation, observed, events, seed) {
  const relation = selectedRelation(scenario, joins, operation, seed);
  assert.equal(relation.parents.length, operation.batch && scenario.limit !== 1 ? 2 : 1);
  const expected = selectedResult(scenario, operation, relation);
  assert.deepEqual(observed, {
    returned: true, result: observeValue(expected), json: JSON.parse(JSON.stringify(expected)), keyOrder: keyOrder(expected),
  }, "Compare the complete selected relation, cardinality, runtime fields, JSON, and own-key sequences");
  assert.deepEqual(events, selectedEvents(backend, scenario, joins, operation, relation),
    "Compare every raw query and original output callback value in operation order");
}

function execute(context, operation) {
  if (operation.surface === "internal") return operation.batch
    ? context.internalAdapter.findSessions([...operation.tokens])
    : context.internalAdapter.findSession(operation.token);
  return operation.batch
    ? context.adapter.findMany(structuredClone(operation.input))
    : context.adapter.findOne(structuredClone(operation.input));
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

async function runtime(backend, scenario, joins, recorder, diagnostics, selected = false) {
  const state = { enabled: false, events: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const database = sqlite ?? memoryAdapter(memory);
  const seed = selected ? selectedRows(scenario) : rows();
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
    for (const operation of selected ? selectedOperations : operations) {
      const context = await betterAuth({ ...optionsFor(scenario, joins, state), database }).$context;
      state.events = [];
      state.enabled = true;
      recorder.events = state.events;
      let observed;
      try {
        observed = await outcome(() => execute(context, operation), diagnostics, {
          backend, scenario: scenario.name, joins, operation: operation.name,
        });
      } finally { state.enabled = false; recorder.events = null; }
      const after = stored();
      try {
        assert.deepEqual(after, before, "Every successful read and reference error must preserve all stored tables");
        if (selected) assertSelectedOperation(backend, scenario, joins, operation, observed, state.events, seed);
        else assertOperation(scenario, joins, operation, observed, state.events, seed);
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
    const selectedCases = [];
    for (const scenario of selectedScenarios) for (const backend of ["memory", "sqlite"]) for (const joins of [false, true]) {
      selectedCases.push(await runtime(backend, scenario, joins, recorder, diagnostics, true));
    }
    assert.equal(selectedCases.length, 28);
    assert.equal(selectedCases.reduce((total, value) => total + value.operations.length, 0), 112);
    cases.push(...selectedCases);
    assert.equal(cases.length, 40);
    assert.equal(cases.reduce((total, value) => total + value.operations.length, 0), 184);
    return { version, scenarios: [...scenarios, ...selectedScenarios], cases };
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
