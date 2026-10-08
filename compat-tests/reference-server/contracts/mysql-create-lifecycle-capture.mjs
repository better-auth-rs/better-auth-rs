import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { queueAfterTransactionHook, runWithTransaction } from "@better-auth/core/context";
import { observeValue } from "./device-where-capture.mjs";

const date = "2030-01-02T03:04:05.000Z";
const now = Date.parse(date);
const originalExpiry = new Date(now + 3_600_000);
const hookExpiry = new Date(now + 7_200_000);
const columns = {
  user: ["id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt"],
  session: ["id", "expiresAt", "token", "createdAt", "updatedAt", "ipAddress", "userAgent", "userId"],
  verification: ["id", "identifier", "value", "expiresAt", "createdAt", "updatedAt"],
};
const targetFields = { user: "name", session: "token", verification: "value" };

export const mysqlCreateLifecycleScenarios = [
  { name: "user-before-cancel-transaction", model: "user", transaction: true, cancel: true },
  { name: "user-written-null-direct", model: "user" },
  { name: "user-written-null-transaction", model: "user", transaction: true },
  { name: "user-after-null-error-direct", model: "user", afterError: true },
  { name: "user-after-null-error-transaction", model: "user", transaction: true, afterError: true },
  { name: "user-written-null-rollback", model: "user", transaction: true, rollback: true },
  { name: "session-secondary-immediate", model: "session", transaction: true, secondary: true },
  { name: "session-secondary-deferred", model: "session", transaction: true, secondary: true, deferred: true },
  { name: "session-secondary-before-cancel", model: "session", transaction: true, secondary: true, cancel: true },
  { name: "session-secondary-deferred-after-error", model: "session", transaction: true, secondary: true, deferred: true, afterError: true },
  { name: "verification-secondary-immediate", model: "verification", transaction: true, secondary: true },
  { name: "verification-secondary-before-cancel", model: "verification", transaction: true, secondary: true, cancel: true },
  { name: "verification-secondary-after-error", model: "verification", transaction: true, secondary: true, afterError: true },
];

const record = value => value === null ? null : { keys: Object.keys(value), fields: observeValue(value) };

async function readStorage(pool) {
  const result = {};
  for (const model of Object.keys(columns)) {
    const [rows] = await pool.promise().query(`SELECT * FROM \`${model}\` ORDER BY id`);
    result[model] = rows.map(row => ({ keys: Object.keys(row), row: observeValue(row) }));
  }
  return result;
}

function user(id, name) {
  return { name, email: `${id}@mysql-readback.test`, emailVerified: true, image: null,
    createdAt: new Date(date), updatedAt: new Date(date), id };
}

async function captureCase(scenario, withDatabase) {
  return withDatabase([], async ({ pool, db, trace }) => {
    const cache = new Map();
    const secondaryStorage = {
      async get(key) {
        const value = cache.get(key)?.value ?? null;
        trace.push({ phase: "cache:get", key, value });
        return value;
      },
      async set(key, value, ttl) {
        trace.push({ phase: "cache:set", key, value, ttl });
        cache.set(key, { value, ttl });
      },
      async delete(key) { trace.push({ phase: "cache:delete", key }); cache.delete(key); },
    };
    const model = scenario.model;
    const field = targetFields[model];
    const patch = model === "user"
      ? { id: "user-submitted-id", name: "Hook user" }
      : model === "session"
        ? { id: "session-submitted-id", token: "hook-token", userId: "owner-b", expiresAt: hookExpiry }
        : { id: "verification-submitted-id", identifier: "hook-identifier", value: "hook-value", expiresAt: hookExpiry };
    const afterError = new Error("creation-after-null-error");
    const rollbackError = new Error("creation-body-rollback");
    let prepared;
    const options = {
      database: { db, type: "mysql", transaction: true },
      baseURL: "http://mysql-readback.test", secret: "mysql-nullable-lifecycle-at-least-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
      advanced: { database: { generateId: ({ model }) => `${model}-generated-id` } },
      session: { storeSessionInDatabase: true }, verification: { storeInDatabase: true },
      ...(scenario.secondary ? { secondaryStorage } : {}),
      plugins: [{
        id: "mysql-nullable-lifecycle",
        schema: { [model]: { fields: { [field]: {
          type: "string", required: true,
          transform: {
            input(value) { trace.push({ phase: "input", field, value: observeValue(value) }); return `${value}:stored`; },
            output(value) { trace.push({ phase: "output", field, value: observeValue(value) }); return value; },
          },
        } } } },
        init() { return { options: { databaseHooks: { [model]: { create: {
          async before(data) {
            trace.push({ phase: "before:plugin", data: record(data) });
            prepared = { ...data, ...patch };
            if (scenario.cancel) return false;
            return { data: patch };
          },
          async after(data) {
            trace.push({ phase: "after:plugin", data: record(data) });
            if (scenario.afterError) throw afterError;
          },
        } } } } }; },
      }],
      databaseHooks: { [model]: { create: {
        async after(data) { trace.push({ phase: "after:application", data: record(data) }); },
      } } },
    };
    const migrations = await getMigrations(options);
    const setup = [await migrations.compileMigrations(),
      `CREATE TRIGGER readback_rewrite_id BEFORE INSERT ON \`${model}\` FOR EACH ROW SET NEW.id = CONCAT('stored-', NEW.id)`];
    await migrations.runMigrations();
    if (model !== "user") {
      for (const [id, name] of [["owner-a", "Owner A"], ["owner-b", "Owner B"]]) {
        const owner = user(id, name);
        await pool.promise().query("INSERT INTO `user` (`id`,`name`,`email`,`emailVerified`,`image`,`createdAt`,`updatedAt`) VALUES (?,?,?,?,?,?,?)",
          columns.user.map(column => owner[column]));
      }
    }
    const context = await betterAuth(options).$context;
    await context.explicitSchemaCheck();
    await pool.promise().query(setup[1]);
    trace.length = 0;
    const before = await readStorage(pool);
    const input = model === "user" ? user("user-submitted-id", "Input user") : model === "session" ? {
      token: "original-token", expiresAt: originalExpiry, createdAt: new Date(date), updatedAt: new Date(date),
      ipAddress: "127.0.0.1", userAgent: "readback-contract",
    } : {
      id: "verification-submitted-id", identifier: "verification-original", value: "original-value",
      expiresAt: originalExpiry, createdAt: new Date(date), updatedAt: new Date(date),
    };
    const create = async () => {
      const result = model === "user" ? await context.internalAdapter.createUser(input)
        : model === "session" ? await context.internalAdapter.createSession("owner-a", false, input, true,
          { deferSecondaryStorageWrites: Boolean(scenario.deferred) })
          : await context.internalAdapter.createVerificationValue(input);
      trace.push({ phase: "body:return", data: record(result) });
      await queueAfterTransactionHook(async () => { trace.push({ phase: "after:tail" }); });
      if (scenario.rollback) throw rollbackError;
      return result;
    };
    let outcome;
    const originalNow = Date.now;
    try {
      Date.now = () => now;
      const result = scenario.transaction ? await runWithTransaction(context.adapter, create) : await create();
      assert.ok(!scenario.afterError && !scenario.rollback, "The configured error must reach the caller");
      outcome = { returned: true, result: record(result) };
    } catch (error) {
      assert.equal(error, scenario.afterError ? afterError : rollbackError, "Preserve the original failure");
      outcome = { returned: false, error: { name: error.name, message: error.message } };
    } finally { Date.now = originalNow; }
    const after = await readStorage(pool);
    const observation = { ...scenario, setup, input: record(input), patch: record(patch), before,
      ...outcome, trace: trace.splice(0), after, cache: [...cache].map(([key, entry]) => ({ key, ...entry })) };
    assertLifecycle(scenario, observation, prepared);
    return observation;
  });
}

function assertLifecycle(scenario, observation, prepared) {
  const label = `${scenario.name}: ${JSON.stringify(observation)}`;
  const { model } = scenario;
  const events = observation.trace;
  const phases = events.map(event => event.phase);
  const sql = events.filter(event => event.phase === "sql");
  const beforeEvent = events.filter(event => event.phase === "before:plugin");
  assert.equal(beforeEvent.length, 1, label);
  assert.equal(events.filter(event => event.phase === "output").length, 0, label);
  const inserts = sql.filter(event => event.sql.startsWith("insert into"));
  assert.equal(inserts.length, scenario.cancel ? 0 : 1, label);
  assert.equal(sql.filter(event => event.sql === "begin").length, 1, label);
  assert.equal(sql.filter(event => event.sql === "rollback").length, scenario.rollback ? 1 : 0, label);
  assert.equal(sql.filter(event => event.sql === "commit").length, scenario.rollback ? 0 : 1, label);
  const inputEvents = events.filter(event => event.phase === "input");
  assert.deepEqual(inputEvents, scenario.cancel ? [] : [{ phase: "input", field: targetFields[model], value: prepared[targetFields[model]] }], label);
  const readbacks = sql.filter(event => event.sql.startsWith(`select * from \`${model}\``));
  assert.deepEqual(readbacks.map(event => ({ sql: event.sql, parameters: event.parameters })), scenario.cancel ? [] : [{
    sql: `select * from \`${model}\` where \`id\` = ? limit ?`, parameters: [patchId(model), 1],
  }], label);
  const expectedStorage = structuredClone(observation.before);
  if (!scenario.cancel && !scenario.rollback) {
    const stored = { ...prepared, id: `stored-${patchId(model)}`, [targetFields[model]]: `${prepared[targetFields[model]]}:stored` };
    if (model === "user") stored.emailVerified = 1;
    expectedStorage[model].push({ keys: columns[model], row: observeValue(stored) });
  }
  assert.deepEqual(observation.after, expectedStorage, label);
  const finalValue = scenario.cancel || !scenario.secondary ? null : record(prepared);
  if (observation.returned) assert.deepEqual(observation.result, finalValue, label);
  const bodyReturns = events.filter(event => event.phase === "body:return");
  assert.deepEqual(bodyReturns, !scenario.transaction && scenario.afterError ? [] : [{ phase: "body:return", data: finalValue }], label);
  const afterEvents = events.filter(event => event.phase === "after:plugin" || event.phase === "after:application");
  assert.deepEqual(afterEvents, scenario.cancel || scenario.rollback ? [] : [
    { phase: "after:plugin", data: finalValue },
    ...scenario.afterError ? [] : [{ phase: "after:application", data: finalValue }],
  ], label);
  const committed = events.findIndex(event => event.phase === "sql" && event.sql === "commit");
  if (afterEvents.length) assert.ok(committed < phases.indexOf("after:plugin"), label);
  if (scenario.transaction && bodyReturns.length) assert.ok(phases.indexOf("body:return") < events.findIndex(event => event.phase === "sql" && ["commit", "rollback"].includes(event.sql)), label);
  assert.equal(phases.filter(phase => phase === "after:tail").length, scenario.afterError || scenario.rollback ? 0 : 1, label);

  const writesSecondary = scenario.secondary && !scenario.cancel && !(scenario.deferred && scenario.afterError);
  const expectedCache = !writesSecondary ? [] : model === "session" ? [
    { key: "active-sessions-owner-a", value: JSON.stringify([{ token: "original-token", expiresAt: originalExpiry.getTime() }]), ttl: 3600 },
    { key: "original-token", value: JSON.stringify({ session: prepared, user: user("owner-a", "Owner A") }), ttl: 3600 },
  ] : [{ key: "verification:verification-original", value: JSON.stringify(prepared), ttl: 7200 }];
  assert.deepEqual(observation.cache, expectedCache, label);
  assert.deepEqual(events.filter(event => event.phase === "cache:set"), expectedCache.map(entry => ({ phase: "cache:set", ...entry })), label);
  assert.deepEqual(events.filter(event => event.phase === "cache:get"), writesSecondary && model === "session"
    ? [{ phase: "cache:get", key: "active-sessions-owner-a", value: null }] : [], label);
  assert.equal(phases.includes("cache:delete"), false, label);
  if (writesSecondary) {
    const firstWrite = phases.indexOf("cache:set");
    if (scenario.deferred) assert.ok(phases.indexOf("after:application") < firstWrite, label);
    else assert.ok(firstWrite < phases.indexOf("body:return") && firstWrite < committed, label);
  }
}

const patchId = model => `${model}-submitted-id`;

export async function captureMysqlCreateLifecycle(withDatabase) {
  const cases = [];
  for (const scenario of mysqlCreateLifecycleScenarios) cases.push(await captureCase(scenario, withDatabase));
  return { now: date, cases };
}
