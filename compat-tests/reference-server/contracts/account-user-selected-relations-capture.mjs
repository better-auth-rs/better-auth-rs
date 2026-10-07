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
const email = "a@account-user-selected-relations.test";
const tables = ["user", "session", "account", "verification"];
const reference = (model, field = "id") => ({ references: { model, field } });
const duplicateIdentity = 'Multiple accounts match the same accountId for provider "provider". Resolve duplicate account identities before continuing.';
const userFields = ["name", "image"];
const accountFields = ["accountId", "userId", "accessToken"];

export const selectedRelationScenarios = [
  { name: "default", populations: [false, true] },
  {
    name: "alternate-account-reference",
    accountFields: { userId: {}, accessToken: reference("user") },
    ownerIds: ["user-b"], accountIds: ["account-b"],
  },
  {
    name: "reverse-user-reference-many",
    accountFields: { userId: {} }, userFields: { image: reference("account") },
    reverse: true, ownerMany: true, ownerIds: ["user-b", "user-c"],
    accountsOne: true, accountIds: ["account-b"],
  },
  {
    name: "reverse-user-reference-many-limit",
    accountFields: { userId: {} }, userFields: { image: reference("account") },
    reverse: true, ownerMany: true, ownerIds: ["user-b"], limit: 1,
    accountsOne: true, accountIds: ["account-b"],
  },
  {
    name: "reverse-user-reference-empty",
    accountFields: { userId: {} }, userFields: { image: reference("account") },
    reverse: true, missingChild: true, ownerMany: true, ownerIds: [],
    accountsOne: true, accountIds: [],
  },
  {
    name: "reverse-user-reference-unique",
    accountFields: { userId: {} }, userFields: { image: { ...reference("account"), unique: true } },
    reverse: true, reverseUnique: true, ownerIds: ["user-b"],
    accountsOne: true, accountIds: ["account-b"],
  },
  {
    name: "unique-account-reference",
    accountFields: { userId: { ...reference("user"), unique: true } },
    accountsOne: true,
  },
  {
    name: "account-output-selects-fallback-owner",
    replacements: { "account.userId": ["user-a", "user-b"] },
    ownerIds: ["user-a"], fallbackOwnerIds: ["user-b"],
  },
  {
    name: "user-output-selects-fallback-account",
    accountFields: { userId: {}, accessToken: { ...reference("user", "image"), unique: true } },
    replacements: { "user.image": ["image-a", "image-b"] },
    imageReference: true, accountsOne: true,
    accountIds: ["account-a"], fallbackAccountIds: ["account-b"],
  },
  { name: "duplicate-account-identities", duplicateIdentity: true },
];

function replace(scenario, model, name, value) {
  const replacement = scenario.replacements?.[`${model}.${name}`];
  return replacement && value === replacement[0] ? replacement[1] : value;
}

function optionsFor(scenario, joins, state) {
  const fields = (model, defaults, declarations) => Object.fromEntries(Object.entries({ ...defaults, ...declarations })
    .map(([name, declaration]) => [name, {
      type: "string", required: false, ...declaration,
      transform: { output(value) {
        if (state.enabled) state.events.push(["output", `${model}.${name}`, observeValue(value)]);
        return replace(scenario, model, name, value);
      } },
    }]));
  return {
    baseURL: "http://account-user-selected-relations.test",
    secret: "account-user-selected-relations-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins, defaultFindManyLimit: scenario.limit ?? 100 } },
    user: { additionalFields: fields("user", { image: {}, name: {} }, scenario.userFields) },
    account: { additionalFields: fields("account", {
      accessToken: {}, accountId: {}, userId: reference("user"),
    }, scenario.accountFields) },
  };
}

function seedRows(scenario) {
  const users = ["a", "b", "c"].map(suffix => ({
    id: `user-${suffix}`, name: `User ${suffix}`, email: `${suffix}@account-user-selected-relations.test`,
    emailVerified: true,
    image: scenario.reverse
      ? scenario.missingChild || scenario.reverseUnique && suffix === "c" ? null : suffix === "a" ? "account-b" : "account-a"
      : `image-${suffix}`,
    createdAt: date, updatedAt: date,
  }));
  const accounts = ["a", "b"].map(suffix => ({
    id: `account-${suffix}`, accountId: suffix === "a" || scenario.duplicateIdentity ? "external-owner" : "external-decoy",
    providerId: "provider", userId: `user-${suffix}`,
    accessToken: scenario.imageReference ? `image-${suffix}` : suffix === "a" ? "user-b" : "user-a",
    refreshToken: null, idToken: null, accessTokenExpiresAt: null, refreshTokenExpiresAt: null,
    scope: null, password: null, createdAt: date, updatedAt: date,
  }));
  return { user: users, account: accounts };
}

function project(scenario, model, row) {
  const fields = model === "user"
    ? ["name", "email", "emailVerified", "image", "createdAt", "updatedAt", "id"]
    : ["accountId", "providerId", "userId", "accessToken", "refreshToken", "idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "password", "createdAt", "updatedAt", "id"];
  return Object.fromEntries(fields.map(name => [name, replace(scenario, model, name, row[name])]));
}

function keyOrder(value, path = []) {
  if (value === null || typeof value !== "object" || value instanceof Date) return [];
  return [{ path, keys: Object.keys(value) }, ...Object.entries(value).flatMap(([key, child]) => keyOrder(child, [...path, key]))];
}

async function outcome(action) {
  try {
    const result = await action();
    return { returned: true, result: observeValue(result), json: JSON.parse(JSON.stringify(result)), keyOrder: keyOrder(result) };
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    assert.ok(error instanceof Error);
    return { returned: false, error: {
      name: error.name, message: error.message,
      properties: observeValue(Object.fromEntries(Object.entries(error))), keys: Object.keys(error),
    } };
  }
}

function execute(context, surface, operation) {
  if (operation === "owner") {
    return surface === "internal"
      ? context.internalAdapter.findAccountOwnerByKey({ providerId: "provider", accountId: "external-owner" })
      : context.adapter.findMany({ model: "account", limit: 2, join: { user: true }, where: [
        { field: "providerId", value: "provider" }, { field: "accountId", value: "external-owner" },
      ] });
  }
  return surface === "internal"
    ? context.internalAdapter.findUserByEmail(email, { includeAccounts: true })
    : context.adapter.findOne({ model: "user", join: { account: true }, where: [{ field: "email", value: email }] });
}

function selectedRows(scenario, joins, operation, rows) {
  const select = (model, ids) => ids.map(id => {
    const row = rows[model].find(row => row.id === id);
    assert.ok(row, `Expected seeded ${model} ${id}`);
    return row;
  });
  if (operation === "owner") {
    return {
      parents: select("account", scenario.duplicateIdentity ? ["account-a", "account-b"] : ["account-a"]),
      children: scenario.duplicateIdentity ? [select("user", ["user-a"]), select("user", ["user-b"])] : [
        select("user", !joins && scenario.fallbackOwnerIds || scenario.ownerIds || ["user-a"]),
      ],
      many: Boolean(scenario.ownerMany), parentModel: "account", childModel: "user",
    };
  }
  return {
    parents: select("user", ["user-a"]),
    children: [select("account", !joins && scenario.fallbackAccountIds || scenario.accountIds || ["account-a"])],
    many: !scenario.accountsOne, parentModel: "user", childModel: "account",
  };
}

function expectedResult(scenario, surface, operation, selected) {
  const { parents, children, many, parentModel, childModel } = selected;
  const joined = children.map(rows => {
    const projected = rows.map(row => project(scenario, childModel, row));
    return many ? projected : projected[0] ?? null;
  });
  if (operation === "owner") {
    if (surface === "adapter") return parents.map((row, index) => ({
      ...project(scenario, parentModel, row), user: joined[index],
    }));
    const account = project(scenario, parentModel, parents[0]);
    return joined[0] === null ? { kind: "orphaned", account } : { kind: "owned", user: joined[0], account };
  }
  const user = project(scenario, parentModel, parents[0]);
  return surface === "adapter" ? { ...user, account: joined[0] } : { user, accounts: joined[0] ?? [] };
}

function expectedEvents(backend, scenario, joins, operation, selected) {
  const { parents, children, many, parentModel, childModel } = selected;
  const event = (model, row, name) => ["output", `${model}.${name}`, observeValue(row[name])];
  const fields = model => model === "user" ? userFields : accountFields;
  const events = [["query", operation === "owner" ? "findMany" : "findOne", parentModel]];
  // findMany projects the parent records concurrently; each parent's child page remains sequential.
  for (const name of fields(parentModel)) for (const row of parents) events.push(event(parentModel, row, name));
  if (!joins) for (const row of parents) {
    const sourceIsNull = operation === "accounts" && scenario.reverse && row.image === null;
    if (!sourceIsNull) events.push(["query", many ? "findMany" : "findOne", childModel]);
  }
  // The existing account-owner-multiple-fields fixture proves SQLite fallback completes each User before the next User.
  if (parents.length === 1 || backend === "sqlite" && !joins) {
    for (const rows of children) for (const row of rows) for (const name of fields(childModel)) events.push(event(childModel, row, name));
  } else {
    assert.equal(many, false, "The duplicate-parent control has one child per parent");
    for (const name of fields(childModel)) for (const rows of children) for (const row of rows) events.push(event(childModel, row, name));
  }
  return events;
}

function assertOperation(backend, scenario, joins, populated, surface, operation, observed, events, rows) {
  if (!populated) {
    const expected = surface === "adapter" && operation === "owner" ? [] : null;
    assert.deepEqual(observed, { returned: true, result: expected, json: expected, keyOrder: keyOrder(expected) });
    assert.deepEqual(events, [["query", operation === "owner" ? "findMany" : "findOne", operation === "owner" ? "account" : "user"]]);
    return;
  }
  const selected = selectedRows(scenario, joins, operation, rows);
  assert.deepEqual(events, expectedEvents(backend, scenario, joins, operation, selected), "Compare every query and callback in order, with the original callback value");
  if (scenario.duplicateIdentity && surface === "internal" && operation === "owner") {
    assert.deepEqual(observed, { returned: false, error: {
      name: "BetterAuthError", message: duplicateIdentity,
      properties: { name: "BetterAuthError" }, keys: ["name"],
    } });
    return;
  }
  const expected = expectedResult(scenario, surface, operation, selected);
  assert.deepEqual(observed, {
    returned: true, result: observeValue(expected), json: JSON.parse(JSON.stringify(expected)), keyOrder: keyOrder(expected),
  }, "Compare the complete result, undefined/Date observations, JSON, and every own-key sequence");
}

async function runtime(backend, scenario, joins, populated, recorder) {
  const state = { events: [], enabled: false };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const memory = Object.fromEntries(tables.map(table => [table, []]));
  const database = sqlite ?? memoryAdapter(memory);
  const baseline = { ...optionsFor({}, joins, state), database };
  const rows = seedRows(scenario);
  const stored = () => Object.fromEntries(tables.map(table => [table, observeValue(sqlite
    ? sqlite.query(`SELECT * FROM "${table}" ORDER BY "id"`).all()
    : memory[table]) ]));
  try {
    // Create one physical catalog before replacing runtime reference metadata.
    if (sqlite) await (await getMigrations(baseline)).runMigrations();
    if (populated) {
      const { adapter } = await betterAuth(baseline).$context;
      for (const model of ["user", "account"]) for (const data of rows[model]) {
        await adapter.create({ model, forceAllowId: true, data });
      }
    }
    const before = stored();
    const operations = [];
    for (const surface of ["adapter", "internal"]) for (const operation of ["owner", "accounts"]) {
      const context = await betterAuth({ ...optionsFor(scenario, joins, state), database }).$context;
      state.events = [];
      state.enabled = true;
      recorder.events = state.events;
      let observed;
      try { observed = await outcome(() => execute(context, surface, operation)); }
      finally { state.enabled = false; recorder.events = null; }
      const after = stored();
      assert.deepEqual(after, before, "Every join and duplicate-identity error must preserve every stored table");
      assertOperation(backend, scenario, joins, populated, surface, operation, observed, state.events, rows);
      operations.push({ surface, operation, events: state.events, ...observed, storageUnchanged: true });
    }
    return { backend, scenario: scenario.name, joins, populated, before, operations, after: stored() };
  } finally { state.enabled = false; recorder.events = null; sqlite?.close(); }
}

export async function captureAccountUserSelectedRelations() {
  const recorder = { events: null };
  let warmup = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return {
    startActiveSpan(name, options, callback) {
      if (name === "account-user-selected-relations-warmup") warmup = true;
      const attributes = options.attributes;
      if (attributes["db.operation.name"] && attributes["db.collection.name"]) {
        recorder.events?.push(["query", attributes["db.operation.name"], attributes["db.collection.name"]]);
      }
      return callback({ end() {}, setAttribute() {}, setStatus() {}, recordException() {} });
    },
  }; } }), true);
  try {
    for (let attempt = 0; attempt < 50 && !warmup; attempt++) {
      await withSpan("account-user-selected-relations-warmup", {}, async () => {});
      if (!warmup) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(warmup, true, "The query recorder must be active before sampling");
    const cases = [];
    for (const scenario of selectedRelationScenarios) for (const joins of [false, true]) {
      for (const backend of ["memory", "sqlite"]) for (const populated of scenario.populations ?? [true]) {
        cases.push(await runtime(backend, scenario, joins, populated, recorder));
      }
    }
    assert.equal(cases.length, 44);
    assert.equal(cases.reduce((count, item) => count + item.operations.length, 0), 176);
    return { version, scenarios: observeValue(selectedRelationScenarios), cases };
  } finally { trace.disable(); }
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureAccountUserSelectedRelations(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
