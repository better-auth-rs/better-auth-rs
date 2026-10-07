import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Database } from "bun:sqlite";
import { createAdapterFactory } from "@better-auth/core/db/adapter";
import { withSpan } from "@better-auth/core/instrumentation";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { observeValue } from "./device-where-capture.mjs";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url));
const require = createRequire(new URL("../package.json", import.meta.url));
const { trace } = require("@opentelemetry/api");
const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

const date = new Date("2030-01-02T03:04:05.000Z");
const tables = ["user", "session", "account", "verification", "organization", "member", "invitation"];
const reference = (model, field = "id") => ({ references: { model, field } });
const missing = "No foreign key found for model user and base model member while performing join operation.";
const multiple = "Multiple foreign keys found for model user and base model member while performing join operation. Only one foreign key is supported.";
export const memberJoinScenarios = [
  { name: "default" },
  { name: "removed-reference", memberFields: { userId: {} }, error: missing },
  { name: "duplicate-member-reference", memberFields: { ownerRef: reference("user") }, error: multiple },
  { name: "duplicate-user-reference", userFields: { memberRef: reference("member"), image: reference("member") }, error: multiple },
  { name: "unknown-member-reference-model", memberFields: { ownerRef: reference("missingModel") }, error: 'Model "missingModel" not found in schema' },
  { name: "unknown-user-reference-model", userFields: { memberRef: reference("missingModel") }, error: 'Model "missingModel" not found in schema' },
  { name: "unknown-user-target-field", memberFields: { userId: reference("user", "missingUserField") }, error: "Field missingUserField not found in model user" },
  { name: "unknown-member-target-field", userFields: { memberRef: reference("member", "missingMemberField") }, error: "Field missingMemberField not found in model member" },
  { name: "owner-reference-replacement", memberFields: { userId: {}, ownerRef: reference("user") }, selected: "user-b" },
  { name: "owner-reference-missing-child", memberFields: { userId: {}, ownerRef: reference("user") }, missingChild: true },
  { name: "reverse-reference-many", userFields: { memberRef: reference("member") }, many: true },
  { name: "reverse-reference-many-limit", userFields: { memberRef: reference("member") }, many: true, limit: 1 },
  { name: "reverse-reference-many-empty", userFields: { memberRef: reference("member") }, many: true, missingChild: true },
  { name: "reverse-reference-unique", userFields: { memberRef: { ...reference("member"), unique: true } }, selected: "user-b" },
  { name: "reverse-reference-unique-empty", userFields: { memberRef: { ...reference("member"), unique: true } }, missingChild: true },
  { name: "member-output-error", failure: "member.role" },
  { name: "user-output-error", failure: "user.name" },
  {
    name: "source-alias-chain",
    memberFields: {
      userId: {}, ownerRef: { fieldName: "lookup", ...reference("user") }, lookup: { fieldName: "stored_lookup" },
    },
    storageFields: { memberFields: { ownerRef: { fieldName: "lookup" }, lookup: { fieldName: "stored_lookup" } } },
    memberSeed: { lookup: "user-c" },
    on: { from: "lookup", to: "id" }, selected: "user-b", selectedFallback: "user-c",
  },
  {
    name: "target-alias-chain",
    userFields: {
      memberRef: { fieldName: "lookup", ...reference("member"), unique: true }, lookup: { fieldName: "stored_lookup" },
    },
    storageFields: { userFields: { memberRef: { fieldName: "lookup" }, lookup: { fieldName: "stored_lookup" } } },
    userSeeds: { a: { lookup: null }, b: { lookup: null }, c: { lookup: "member-a" } },
    on: { from: "id", to: "lookup" }, selected: "user-b", selectedFallback: "user-c",
  },
  {
    name: "reverse-reference-fractional-limit", userFields: { memberRef: reference("member") },
    many: true, limit: 1.5, backends: ["memory"], childCounts: { native: 2, fallback: 1 },
  },
  {
    name: "reverse-reference-nan-limit", userFields: { memberRef: reference("member") },
    many: true, limit: NaN, backends: ["memory"], childCounts: { native: 2, fallback: 0 },
  },
  {
    name: "reverse-reference-negative-limit", userFields: { memberRef: reference("member") },
    many: true, limit: -1, backends: ["memory"], childCounts: { native: 0, fallback: 1 },
  },
];

function optionsFor(scenario, joins, state) {
  const field = (model, name, declaration = {}) => ({
    type: "string", required: false, ...declaration,
    transform: {
      output(value) {
        if (state.enabled) {
          state.events.push(["output", `${model}.${name}`, observeValue(value)]);
          if (scenario.failure === `${model}.${name}`) throw state.failure;
        }
        return value;
      },
    },
  });
  const fields = (model, declarations, configured) => Object.fromEntries(Object.entries({ ...declarations, ...configured })
    .map(([name, declaration]) => [name, field(model, name, { ...declarations[name], ...declaration })]));
  // Native replacements retain their schema positions despite the declaration order below.
  const plugin = { schema: { member: { additionalFields: fields("member", {
    label: {}, detail: {}, role: {}, ownerRef: { fieldName: "stored_owner_ref" },
  }, scenario.memberFields) } } };
  return {
    plugin,
    options: {
      baseURL: "http://member-join-reference.test",
      secret: "member-join-reference-contract-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      advanced: { database: { joins, defaultFindManyLimit: scenario.limit ?? 100 } },
      user: { additionalFields: fields("user", {
        image: {}, name: {}, memberRef: { fieldName: "stored_member_ref" },
      }, scenario.userFields) },
      plugins: [organization(plugin)],
    },
  };
}

function keyOrder(value, path = []) {
  if (value === null || typeof value !== "object" || value instanceof Date) return [];
  return [{ path, keys: Object.keys(value) }, ...Object.entries(value).flatMap(([key, child]) => keyOrder(child, [...path, key]))];
}

async function outcome(action, state) {
  try {
    const result = await action();
    return { returned: true, result: observeValue(result), json: JSON.parse(JSON.stringify(result)), keyOrder: keyOrder(result) };
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    assert.ok(error instanceof Error);
    // Preserve observable error properties and callback identity; exclude host-dependent stack traces.
    return { returned: false, error: {
      name: error.name, message: error.message, sameCallbackError: error === state.failure,
      properties: observeValue(Object.fromEntries(Object.entries(error))), keys: Object.keys(error),
    } };
  }
}

function execute(adapter, plugin, surface, path) {
  if (surface === "organization") {
    const org = getOrgAdapter({ adapter }, plugin);
    return path === "by-org"
      ? org.findMemberByOrgId({ userId: "user-a", organizationId: "organization-a" })
      : org.findMemberById("member-a");
  }
  return adapter.findOne({ model: "member", join: { user: true }, where: path === "by-org" ? [
    { field: "userId", value: "user-a" }, { field: "organizationId", value: "organization-a" },
  ] : [{ field: "id", value: "member-a" }] });
}

async function boundary(scenario, joins) {
  const operations = [];
  for (const path of ["by-org", "by-id"]) {
    const state = { events: [], enabled: true };
    const { options } = optionsFor(scenario, joins, state);
    // The upstream factory validates and resolves the join before the raw reader returns no row.
    const adapter = createAdapterFactory({
      config: { adapterId: "member-join-reference-boundary", supportsJSON: true },
      adapter: () => ({ async findOne(input) { state.events.push(["findOne", observeValue(input)]); return null; } }),
    })(options);
    const result = await outcome(() => execute(adapter, undefined, "adapter", path), state);
    if (scenario.error) {
      assert.equal(result.returned, false);
      assert.equal(result.error.message, scenario.error);
      assert.deepEqual(state.events, [], "Reference failures must precede raw reads and output callbacks");
    } else {
      assert.equal(result.returned, true);
      assert.equal(result.result, null);
      assert.equal(state.events.length, 1);
      if (joins) {
        const selected = state.events[0][1].join.user;
        const reverse = Boolean(scenario.userFields?.memberRef?.references);
        assert.deepEqual(selected.on, scenario.on ?? {
          from: reverse ? "id" : scenario.memberFields?.ownerRef?.references ? "stored_owner_ref" : "userId",
          to: reverse ? "stored_member_ref" : "id",
        });
        assert.equal(selected.relation, scenario.many ? "one-to-many" : "one-to-one");
        assert.deepEqual(selected.limit, observeValue(scenario.many ? scenario.limit ?? 100 : 1));
      }
    }
    operations.push({ path, events: state.events, ...result });
  }
  return { scenario: scenario.name, joins, operations };
}

async function seed(adapter, scenario) {
  const create = (model, data) => adapter.create({ model, forceAllowId: true, data: { createdAt: date, updatedAt: date, ...data } });
  for (const suffix of ["a", "b", "c"]) {
    const matches = !scenario.missingChild && (suffix === "b" || suffix === "c" && scenario.many);
    await create("user", {
      id: `user-${suffix}`, name: `User ${suffix}`, email: `${suffix}@member-join-reference.test`,
      emailVerified: true, image: `image-${suffix}`, memberRef: matches ? "member-a" : null,
      ...scenario.userSeeds?.[suffix],
    });
  }
  await create("organization", { id: "organization-a", name: "Join organization", slug: "join-organization", logo: null, metadata: null });
  await create("member", {
    id: "member-a", organizationId: "organization-a", userId: "user-a", role: "member",
    ownerRef: scenario.missingChild ? "missing-user" : "user-b", label: "Member label", detail: "Member detail",
    ...scenario.memberSeed,
  });
}

function assertOperation(scenario, joins, populated, surface, path, result, events) {
  if (scenario.error) {
    assert.equal(result.returned, false);
    assert.equal(result.error.message, scenario.error);
    assert.deepEqual(events, [], "Reference failures must precede reads and output callbacks");
    return;
  }
  assert.ok(events.some(event => event[0] === "query"), "A valid join must execute a raw read");
  if (!populated) {
    assert.equal(result.returned, true);
    assert.equal(result.result, null);
    assert.ok(events.every(event => event[0] === "query"));
    return;
  }
  const callbacks = events.filter(event => event[0] === "output");
  const parentFields = [
    ...(scenario.memberFields?.userId ? ["member.userId"] : []),
    "member.role", "member.label", "member.detail", "member.ownerRef",
    ...(scenario.memberFields?.lookup ? ["member.lookup"] : []),
  ];
  if (scenario.failure) {
    assert.equal(result.returned, false);
    assert.equal(result.error.sameCallbackError, true);
    assert.deepEqual(callbacks.map(event => event[1]), scenario.failure === "member.role"
      ? ["member.role"] : [...parentFields, "user.name"]);
    return;
  }
  const childCount = scenario.childCounts?.[joins ? "native" : "fallback"]
    ?? (scenario.missingChild ? 0 : scenario.many ? scenario.limit ?? 2 : 1);
  assert.deepEqual(callbacks.map(event => event[1]), [
    ...parentFields,
    ...Array.from({ length: childCount }, () => [
      "user.name", "user.image", "user.memberRef", ...(scenario.userFields?.lookup ? ["user.lookup"] : []),
    ]).flat(),
  ]);
  if (scenario.missingChild && !scenario.many && surface === "organization" && path === "by-id") {
    assert.equal(result.returned, false);
    assert.equal(result.error.name, "TypeError");
    assert.equal(result.error.sameCallbackError, false);
    return;
  }
  assert.equal(result.returned, true);
  if (scenario.many) {
    if (surface === "adapter") {
      assert.ok(Array.isArray(result.result.user));
      assert.equal(result.result.user.length, childCount);
    } else {
      assert.deepEqual(result.json.user, {});
      assert.deepEqual(result.result.user, Object.fromEntries(["id", "name", "email", "image"].map(key => [key, { type: "undefined" }])));
    }
  } else if (scenario.missingChild) {
    assert.equal(surface === "adapter" ? result.result.user : result.result, null);
  } else {
    const selected = joins ? scenario.selected : scenario.selectedFallback ?? scenario.selected;
    assert.equal(result.result.user.id, selected ?? "user-a");
  }
}

async function runtime(backend, scenario, joins, populated, recorder) {
  const state = { events: [], enabled: false, failure: new APIError("BAD_REQUEST", {
    code: "MEMBER_JOIN_OUTPUT_REJECTED", message: "Member join output callback rejected",
  }) };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const memory = Object.fromEntries(tables.map(table => [table, []]));
  const database = sqlite ?? memoryAdapter(memory);
  const baseline = { ...optionsFor(scenario.storageFields ?? {}, joins, state).options, database };
  const stored = () => Object.fromEntries(tables.map(table => [table, observeValue(sqlite
    ? sqlite.query(`SELECT * FROM "${table}" ORDER BY "id"`).all()
    : memory[table]) ]));
  try {
    // The physical catalog stays fixed so runtime reference removal and replacement remain independently observable.
    if (sqlite) await (await getMigrations(baseline)).runMigrations();
    if (populated) await seed((await betterAuth(baseline).$context).adapter, scenario);
    const before = stored();
    const operations = [];
    for (const surface of ["adapter", "organization"]) for (const path of ["by-org", "by-id"]) {
      const { options, plugin } = optionsFor(scenario, joins, state);
      const { adapter } = await betterAuth({ ...options, database }).$context;
      state.events = [];
      state.enabled = true;
      recorder.events = state.events;
      let result;
      try { result = await outcome(() => execute(adapter, plugin, surface, path), state); }
      finally { state.enabled = false; recorder.events = null; }
      const after = stored();
      assert.deepEqual(after, before, "Join reads and callback failures must preserve every stored table");
      assertOperation(scenario, joins, populated, surface, path, result, state.events);
      operations.push({ surface, path, events: state.events, ...result, storageUnchanged: true });
    }
    return { backend, scenario: scenario.name, joins, populated, before, operations, after: stored() };
  } finally { state.enabled = false; recorder.events = null; sqlite?.close(); }
}

export async function captureOrganizationMemberJoinReferences() {
  const recorder = { events: null };
  let warmup = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return {
    startActiveSpan(name, options, callback) {
      if (name === "member-join-reference-warmup") warmup = true;
      const attributes = options.attributes;
      if (attributes["db.operation.name"] && attributes["db.collection.name"]) {
        recorder.events?.push(["query", attributes["db.operation.name"], attributes["db.collection.name"]]);
      }
      return callback({ end() {}, setAttribute() {}, setStatus() {}, recordException() {} });
    },
  }; } }), true);
  try {
    // Upstream loads OpenTelemetry asynchronously; require the query recorder before sampling.
    for (let attempt = 0; attempt < 50 && !warmup; attempt++) {
      await withSpan("member-join-reference-warmup", {}, async () => {});
      if (!warmup) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(warmup, true, "The query recorder must be active before sampling");
    const boundaries = [];
    const cases = [];
    for (const scenario of memberJoinScenarios) for (const joins of [false, true]) {
      boundaries.push(await boundary(scenario, joins));
      for (const backend of scenario.backends ?? ["memory", "sqlite"]) for (const populated of [false, true]) {
        cases.push(await runtime(backend, scenario, joins, populated, recorder));
      }
    }
    return { version, scenarios: observeValue(memberJoinScenarios), boundaries, cases };
  } finally { trace.disable(); }
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureOrganizationMemberJoinReferences(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
