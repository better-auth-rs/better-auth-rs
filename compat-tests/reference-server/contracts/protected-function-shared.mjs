import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { buildSyntheticUserOutput, parseInputData, parseUserOutput } from "better-auth/db";
import { runWithEndpointContext, runWithTransaction } from "@better-auth/core/context";

export const protectedFunctionDate = "2030-01-02T03:04:05.000Z";
export const protectedFunctionTables = ["user", "session", "account", "verification"];
export const protectedFunctionScenarios = [
  { name: "raw-string", result: "string" },
  { name: "raw-undefined", result: "undefined" },
  { name: "raw-date", result: "date", fieldType: "date" },
  { name: "raw-object", result: "object", fieldType: "json" },
  { name: "raw-throws", result: "throws" },
  { name: "raw-returned-function", result: "function" },
  { name: "input-call", result: "string", input: "call" },
  { name: "input-replace", result: "string", input: "replace" },
  { name: "input-throws", result: "string", input: "throws" },
  { name: "output-call", result: "string", output: "call" },
  { name: "output-replace", result: "string", output: "replace" },
  { name: "output-throws", result: "string", output: "throws" },
  { name: "hidden-function", result: "string", returned: false },
  { name: "missing-string", result: "string", missing: true },
  { name: "missing-undefined", result: "undefined", missing: true },
];

export function createProtectedFunctionObserver() {
  const labels = new WeakMap();
  const functions = [];
  function register(value, label) {
    if (!labels.has(value)) {
      const identity = label ?? `function-${functions.length + 1}`;
      labels.set(value, identity);
      functions.push({
        identity, name: value.name, length: value.length,
        source: Function.prototype.toString.call(value), string: String(value),
        ownKeys: Reflect.ownKeys(value).map(key => typeof key === "symbol" ? { symbol: String(key) } : key),
      });
    }
    return labels.get(value);
  }
  function observe(value) {
    if (value === undefined) return { type: "undefined" };
    if (typeof value === "function") return { type: "function", identity: register(value) };
    if (value instanceof Date) return { type: "date", value: Number.isNaN(value.getTime()) ? "Invalid Date" : value.toISOString() };
    if (typeof value === "number" && !Number.isFinite(value)) return { type: "number", value: String(value) };
    if (typeof value === "bigint") return { type: "bigint", value: String(value) };
    if (typeof value === "symbol") return { type: "symbol", value: String(value) };
    if (Array.isArray(value)) return value.map(observe);
    if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, field]) => [key, observe(field)]));
    return value;
  }
  function error(caught) {
    if (caught instanceof assert.AssertionError) throw caught;
    if (!(caught instanceof Error)) return { thrown: observe(caught) };
    // Stack paths identify the capture host. Retain the complete message and all other own properties.
    const properties = Object.fromEntries(Object.getOwnPropertyNames(caught)
      .filter(key => !["stack", "name", "message"].includes(key)).map(key => [key, observe(caught[key])]));
    return { name: caught.name, message: caught.message, properties };
  }
  return { observe, register, error, functions };
}

export function protectedFunctionUser(id, fields = {}) {
  return {
    id, name: "Protected function owner", email: `${id}@protected-function.test`,
    emailVerified: false, image: null,
    createdAt: new Date(protectedFunctionDate), updatedAt: new Date(protectedFunctionDate),
    ...fields,
  };
}

export function createProtectedFunctionHarness(scenario) {
  const observation = createProtectedFunctionObserver();
  const { observe, register } = observation;
  const events = [];
  const counts = { factory: 0, returnedFunction: 0, validator: 0, input: 0, output: 0, admission: 0, before: 0, after: 0, generateId: 0 };
  let admitted;
  let field;
  function returnedFunction() {
    counts.returnedFunction += 1;
    events.push({ phase: "returned-function", arguments: observe([...arguments]) });
    return "returned-function-value";
  }
  register(returnedFunction, "returned-function");
  function protectedDefault() {
    counts.factory += 1;
    events.push({
      phase: "default", arguments: observe([...arguments]),
      thisIsDeclaration: this === field, thisType: typeof this,
    });
    switch (scenario.result) {
      case "string": return "factory-value";
      case "undefined": return undefined;
      case "date": return new Date(protectedFunctionDate);
      case "object": return { source: "factory", ownUndefined: undefined };
      case "function": return returnedFunction;
      case "throws": throw new Error("protected-default-failed");
      default: throw new Error(`Unknown factory result: ${scenario.result}`);
    }
  }
  register(protectedDefault, "default-function");
  function transform(phase, value) {
    counts[phase] += 1;
    events.push({ phase, value: observe(value), sameDefault: value === protectedDefault, sameReturned: value === returnedFunction });
    if (typeof value !== "function") return value;
    switch (scenario[phase]) {
      case "call": return value();
      case "replace": return `${phase}-replacement`;
      case "throws": throw new Error(`protected-${phase}-failed`);
      default: return value;
    }
  }
  field = {
    type: scenario.fieldType ?? "string", required: false, input: false,
    returned: scenario.returned !== false, defaultValue: protectedDefault,
    validator: { input: { "~standard": { validate(value) {
      counts.validator += 1;
      events.push({ phase: "validator", value: observe(value) });
      return { value };
    } } } },
    transform: { input(value) { return transform("input", value); }, output(value) { return transform("output", value); } },
  };
  const fields = { protectedValue: field };
  const options = {
    baseURL: "http://protected-function.test",
    secret: "protected-function-contract-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    advanced: { database: { generateId({ model }) {
      counts.generateId += 1;
      const id = `${model}-generated-${counts.generateId}`;
      events.push({ phase: "generate-id", model, id });
      return id;
    } } },
    user: {
      additionalFields: fields,
      validateUserInfo({ user, source }) {
        counts.admission += 1;
        admitted = user;
        events.push({ phase: "admission", user: observe(user), source: observe(source), sameDefault: user.protectedValue === protectedDefault });
      },
    },
    databaseHooks: { user: { create: {
      before(user) {
        counts.before += 1;
        events.push({ phase: "before", user: observe(user), sameAdmission: user === admitted, sameDefault: user.protectedValue === protectedDefault });
      },
      after(user) {
        counts.after += 1;
        events.push({ phase: "after", user: observe(user), sameDefault: user?.protectedValue === protectedDefault });
      },
    } } },
  };
  function parse(action = "create", data = scenario.missing ? {} : { protectedValue: "submitted" }) {
    return parseInputData(data, { action, fields });
  }
  function snapshot() { return { counts: { ...counts }, events: events.splice(0) }; }
  return { ...observation, options, fields, events, counts, snapshot, parse, defaultFunction: protectedDefault, returnedFunction };
}

export async function observeProtectedFunction({ options, query, backend, readStorage }, scenario, harness) {
  const { observe, error, events, snapshot } = harness;
  const context = await betterAuth(options).$context;
  const { adapter, internalAdapter } = context;
  const quote = name => backend === "mysql" ? `\`${name}\`` : `"${name}"`;
  const storage = readStorage ?? (async () => {
    const tables = {};
    for (const table of protectedFunctionTables) tables[table] = await query(`SELECT * FROM ${quote(table)} ORDER BY ${quote("id")}`, []);
    return tables;
  });
  const initial = { ...snapshot(), storage: observe(await storage()) };
  const operations = [];
  async function operation(name, execute) {
    const before = { counts: { ...harness.counts }, storage: observe(await storage()) };
    let value;
    let outcome;
    try {
      value = await execute();
      outcome = { returned: true, result: observe(value) };
    } catch (caught) {
      outcome = { returned: false, error: error(caught) };
    }
    operations.push({ name, before, ...outcome, ...snapshot(), storage: observe(await storage()) });
    return { ...outcome, value };
  }
  const where = id => [{ field: "id", value: id }];
  const read = id => adapter.findOne({ model: "user", where: where(id) });
  async function reset(name) {
    await operation(name, () => adapter.deleteMany({ model: "user", where: [] }));
    assert.deepEqual((await storage()).user, [], "Each independent lifecycle must start with an empty User table");
  }
  function parsedUser(id) {
    const factoryCalls = harness.counts.factory;
    const validatorCalls = harness.counts.validator;
    const inputCalls = harness.counts.input;
    const parsed = harness.parse();
    assert.equal(harness.counts.factory - factoryCalls, scenario.missing ? 1 : 0);
    assert.equal(harness.counts.validator, validatorCalls);
    assert.equal(harness.counts.input, inputCalls);
    if (!scenario.missing) assert.equal(parsed.protectedValue, harness.defaultFunction);
    events.push({ phase: "parsed", fields: observe(parsed), ownKeys: Object.keys(parsed), sameDefault: parsed.protectedValue === harness.defaultFunction });
    return protectedFunctionUser(id, parsed);
  }
  function publicOutput(user) {
    events.push({ phase: "public-clone:start", user: observe(user) });
    const output = parseUserOutput(options, user);
    events.push({ phase: "public-clone:return", user: observe(output) });
    return { user: output, json: JSON.stringify({ user: output }) };
  }

  await operation("direct:create", () => adapter.create({ model: "user", forceAllowId: true, data: parsedUser("direct-user") }));
  const directRead = await operation("direct:read", () => read("direct-user"));
  if (directRead.returned && directRead.value !== null) await operation("direct:public-output", () => publicOutput(directRead.value));
  await operation("direct:json-only", () => {
    const fn = harness.defaultFunction;
    return { object: JSON.stringify({ value: fn }), array: JSON.stringify([fn]), root: JSON.stringify(fn) };
  });
  await reset("direct:delete");

  const baseline = scenario.fieldType === "date" ? new Date(protectedFunctionDate)
    : scenario.fieldType === "json" ? { source: "baseline" } : "baseline";
  const seeded = await operation("update:seed", () => adapter.create({ model: "user", forceAllowId: true, data: protectedFunctionUser("updated-user", { protectedValue: baseline }) }));
  assert.equal(seeded.returned, true, "The update baseline must be stored before the function update");
  assert.notEqual(seeded.value, null, "The update baseline must be returned");
  assert.equal((await storage()).user.length, 1, "The function update must target an existing row");
  await operation("update:function", () => adapter.update({ model: "user", where: where("updated-user"), update: {
    protectedValue: harness.defaultFunction, updatedAt: new Date(protectedFunctionDate),
  } }));
  const updatedRead = await operation("update:read", () => read("updated-user"));
  if (updatedRead.returned && updatedRead.value !== null) await operation("update:public-output", () => publicOutput(updatedRead.value));
  await reset("update:delete");

  await operation("transaction:create-and-commit", async () => {
    const result = await adapter.transaction(async current => {
      events.push({ phase: "transaction:enter" });
      const user = await current.create({ model: "user", forceAllowId: true, data: parsedUser("transaction-user") });
      events.push({ phase: "transaction:body-return", user: observe(user) });
      return user;
    });
    events.push({ phase: "transaction:committed" });
    return result;
  });
  await operation("transaction:next-snapshot", async () => {
    const result = await adapter.transaction(async current => {
      events.push({ phase: "next-transaction:enter" });
      return current.findMany({ model: "user" });
    });
    events.push({ phase: "next-transaction:committed" });
    return result;
  });
  await reset("transaction:delete");

  for (const withPublicOutput of [false, true]) {
    const label = withPublicOutput ? "internal:transaction-public" : "internal:transaction-native";
    await operation(label, async () => {
      const result = await runWithEndpointContext({ context }, () => runWithTransaction(adapter, async () => {
        events.push({ phase: "internal-transaction:enter" });
        const user = await internalAdapter.createUser(parsedUser(label.replaceAll(":", "-")), { method: "contract" });
        events.push({ phase: "internal:create-return", user: observe(user) });
        const output = withPublicOutput ? publicOutput(user) : user;
        events.push({ phase: "internal-transaction:body-return", result: observe(output) });
        return output;
      }));
      events.push({ phase: "internal-transaction:committed" });
      return result;
    });
    await reset(`${label}:delete`);
  }

  for (const shape of ["provided", "missing", "undefined"]) {
    await operation(`synthetic:${shape}`, () => {
      const fields = shape === "provided" ? { protectedValue: harness.defaultFunction }
        : shape === "undefined" ? { protectedValue: undefined } : {};
      const user = buildSyntheticUserOutput(options, protectedFunctionUser("synthetic-user", fields));
      events.push({ phase: "synthetic:return", user: observe(user), sameDefault: user.protectedValue === harness.defaultFunction });
      return publicOutput(user);
    });
  }
  const observation = { scenario, initial, operations, functions: harness.functions, final: { ...snapshot(), storage: observe(await storage()) } };
  assertProtectedFunctionLifecycle(observation, backend);
  return observation;
}

function assertProtectedFunctionLifecycle(observation, backend) {
  const { scenario, operations } = observation;
  const memory = backend === "memory";
  const convertedInput = ["call", "replace"].includes(scenario.input);
  const convertedOutput = ["call", "replace"].includes(scenario.output);
  const rawCreatedFunction = !scenario.missing && !convertedInput;
  const createFails = scenario.input === "throws" || scenario.output === "throws"
    || (!memory && rawCreatedFunction);
  const updateFails = scenario.input === "throws" || scenario.output === "throws"
    || (!memory && !convertedInput);
  const get = name => {
    const operation = operations.find(operation => operation.name === name);
    assert.ok(operation, `${backend}/${scenario.name}: missing ${name}`);
    return operation;
  };
  const expectReturned = (name, returned) => {
    const operation = get(name);
    assert.equal(operation.returned, returned, `${backend}/${scenario.name}/${name}`);
    return operation;
  };
  const phaseCount = (operation, phase) => operation.events.filter(event => event.phase === phase).length;
  const unchanged = operation => assert.deepEqual(operation.storage, operation.before.storage, `${backend}/${scenario.name}/${operation.name}: storage must remain unchanged`);
  const cloneFailed = operation => {
    assert.equal(operation.returned, false);
    assert.equal(operation.error.name, "DataCloneError");
  };
  const publicCreateFails = memory && rawCreatedFunction && !convertedOutput;

  const direct = expectReturned("direct:create", !createFails);
  assert.equal(direct.storage.user.length, createFails && !(memory && scenario.output === "throws") ? 0 : 1);
  const directRead = expectReturned("direct:read", !(memory && scenario.output === "throws"));
  if (directRead.returned && directRead.result !== null) {
    const output = expectReturned("direct:public-output", !publicCreateFails);
    if (publicCreateFails) cloneFailed(output);
    unchanged(output);
  }
  const json = expectReturned("direct:json-only", true);
  assert.deepEqual(json.result, { object: "{}", array: "[null]", root: { type: "undefined" } });
  assert.equal(json.counts.factory, json.before.counts.factory);
  const update = expectReturned("update:function", !updateFails);
  assert.equal(update.storage.user.length, 1);
  if (updateFails && !(memory && scenario.output === "throws")) unchanged(update);
  const updateRead = expectReturned("update:read", !(memory && scenario.output === "throws"));
  if (updateRead.returned && updateRead.result !== null) {
    const publicUpdateFails = memory && !convertedInput && !convertedOutput && scenario.input !== "throws";
    const output = expectReturned("update:public-output", !publicUpdateFails);
    if (publicUpdateFails) cloneFailed(output);
    unchanged(output);
  }

  const transaction = expectReturned("transaction:create-and-commit", !createFails);
  assert.equal(phaseCount(transaction, "transaction:enter"), 1);
  assert.equal(phaseCount(transaction, "transaction:body-return"), createFails ? 0 : 1);
  assert.equal(phaseCount(transaction, "transaction:committed"), createFails ? 0 : 1);
  assert.equal(transaction.storage.user.length, createFails ? 0 : 1);
  if (createFails) unchanged(transaction);
  const snapshotFails = memory && !createFails && rawCreatedFunction;
  const next = expectReturned("transaction:next-snapshot", !snapshotFails);
  assert.equal(phaseCount(next, "next-transaction:enter"), snapshotFails ? 0 : 1);
  assert.equal(phaseCount(next, "next-transaction:committed"), snapshotFails ? 0 : 1);
  if (snapshotFails) cloneFailed(next);
  unchanged(next);

  for (const withPublicOutput of [false, true]) {
    const name = withPublicOutput ? "internal:transaction-public" : "internal:transaction-native";
    const fails = createFails || (withPublicOutput && publicCreateFails);
    const internal = expectReturned(name, !fails);
    assert.equal(phaseCount(internal, "internal-transaction:enter"), 1);
    assert.equal(phaseCount(internal, "admission"), 1);
    assert.equal(phaseCount(internal, "before"), 1);
    assert.equal(internal.events.find(event => event.phase === "before").sameAdmission, true);
    assert.equal(phaseCount(internal, "internal:create-return"), createFails ? 0 : 1);
    assert.equal(phaseCount(internal, "internal-transaction:body-return"), fails ? 0 : 1);
    assert.equal(phaseCount(internal, "internal-transaction:committed"), fails ? 0 : 1);
    assert.equal(phaseCount(internal, "after"), fails ? 0 : 1);
    assert.equal(internal.storage.user.length, fails ? 0 : 1);
    if (fails) unchanged(internal);
    if (!createFails && withPublicOutput && publicCreateFails) {
      assert.equal(phaseCount(internal, "public-clone:start"), 1);
      assert.equal(phaseCount(internal, "public-clone:return"), 0);
      cloneFailed(internal);
    }
  }

  for (const shape of ["provided", "missing", "undefined"]) {
    const hidden = scenario.returned === false;
    const factoryThrows = !hidden && shape !== "provided" && scenario.result === "throws";
    const cloneThrows = !hidden && (shape === "provided" || scenario.result === "function");
    const synthetic = expectReturned(`synthetic:${shape}`, !(factoryThrows || cloneThrows));
    assert.equal(synthetic.counts.factory - synthetic.before.counts.factory, hidden || shape === "provided" ? 0 : 1);
    assert.equal(synthetic.counts.input, synthetic.before.counts.input);
    assert.equal(synthetic.counts.output, synthetic.before.counts.output);
    if (cloneThrows) cloneFailed(synthetic);
    if (factoryThrows) assert.equal(synthetic.error.message, "protected-default-failed");
    unchanged(synthetic);
  }
  for (const operation of operations) {
    if (operation.name.endsWith(":delete")) {
      assert.equal(operation.returned, true);
      assert.deepEqual(operation.storage.user, []);
    }
    assert.equal(operation.counts.validator, 0);
    for (const table of protectedFunctionTables.filter(table => table !== "user")) assert.deepEqual(operation.storage[table], []);
  }
  if (!memory && !scenario.missing && !convertedInput && scenario.input !== "throws") {
    for (const name of ["direct:create", "update:function", "transaction:create-and-commit", "internal:transaction-native", "internal:transaction-public"]) {
      const operation = get(name);
      const calls = operation.events.filter(event => event.phase === "default");
      assert.equal(calls.length, 1, `${backend}/${scenario.name}/${name}: Kysely must invoke the function once`);
      assert.equal(calls[0].arguments.length, 1);
      assert.equal(calls[0].arguments[0].type, "function");
      unchanged(operation);
    }
  }
}
