import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { queueAfterTransactionHook, runWithTransaction } from "@better-auth/core/context";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { observeValue } from "./device-where-capture.mjs";

const version = "1.7.6";
for (const packageName of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${packageName}/package.json`, import.meta.url), "utf8")).version, version);
}

const tables = ["user", "session", "account", "verification"];
const seedDate = new Date("2030-01-02T03:04:05.000Z");
const expiresAt = new Date("2100-01-02T03:04:05.000Z");
const owner = {
  id: "owner", name: "Original", email: "owner@secondary-user-refresh.test", emailVerified: true,
  image: null, createdAt: seedDate, updatedAt: seedDate,
};
const indexKey = "active-sessions-owner";
const refreshMessage = "Failed to refresh committed user sessions in secondary storage";
export const secondaryUserRefreshScenarios = [
  { name: "immediate-refresh-error", transaction: false },
  { name: "committed-refresh-error", transaction: true },
  { name: "missing-immediate", transaction: false, missing: true },
  { name: "cancel-committed", transaction: true, cancel: true },
  { name: "after-error-immediate", transaction: false, afterError: true },
  { name: "after-error-committed", transaction: true, afterError: true },
  { name: "rollback", transaction: true, rollback: true },
  { name: "parallel-partial", transaction: false, parallel: true },
  { name: "malformed-cache-envelope", transaction: false, malformed: true },
];

function seedCache(scenario) {
  const activeTokens = scenario.malformed ? ["token-a"] : ["token-a", "token-b"];
  const values = new Map([[indexKey, JSON.stringify(activeTokens.map(token => ({ token, expiresAt: expiresAt.getTime() })))]]);
  for (const suffix of ["a", "b"]) {
    const session = {
      id: `session-${suffix}`, token: `token-${suffix}`, userId: owner.id, expiresAt,
      createdAt: seedDate, updatedAt: seedDate, ipAddress: null, userAgent: `agent-${suffix}`,
    };
    values.set(`token-${suffix}`, JSON.stringify({ session, user: owner }));
  }
  if (scenario.malformed) values.set("token-a", "{}");
  return values;
}

function snapshot(value, failures) {
  if (value instanceof Error) return {
    type: "error", name: value.name, message: value.message,
    keys: Object.keys(value),
    properties: Object.fromEntries(Object.entries(value).map(([key, child]) => [key, snapshot(child, failures)])),
    injected: failures.get(value) ?? null,
  };
  if (value instanceof Date || value === undefined) return observeValue(value);
  if (Array.isArray(value)) return value.map(child => snapshot(child, failures));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, snapshot(child, failures)]));
  return observeValue(value);
}

function normalize(value, updatedAt) {
  if (typeof value === "string" && updatedAt) return value.replaceAll(updatedAt, "<user.updatedAt>");
  if (Array.isArray(value)) return value.map(child => normalize(child, updatedAt));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, normalize(child, updatedAt)]));
  return value;
}

async function captureCase(backend, scenario) {
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const memory = Object.fromEntries(tables.map(table => [table, []]));
  const events = [];
  const cache = seedCache(scenario);
  const cacheFailure = new Error("refresh-cache-failure");
  const afterFailure = new Error("refresh-after-hook-failure");
  const rollbackFailure = new Error("refresh-transaction-rollback");
  const failures = new Map([[cacheFailure, "cache"], [afterFailure, "after"], [rollbackFailure, "rollback"]]);
  const gates = Object.fromEntries(["token-a", "token-b"].map(token => [token, {
    entered: Promise.withResolvers(), release: Promise.withResolvers(),
  }]));
  const siblingFinished = Promise.withResolvers();
  let enabled = false;
  let updatedAt;
  let start;
  let end;
  const record = event => { if (enabled) events.push(snapshot(event, failures)); };
  const cacheSnapshot = () => [...cache].map(([key, value]) => ({ key, value }));
  const databaseSnapshot = () => snapshot(Object.fromEntries(tables.map(table => [table, sqlite
    ? sqlite.query(`SELECT * FROM "${table}" ORDER BY "id"`).all() : memory[table]])), failures);
  const options = {
    database: sqlite ?? memoryAdapter(memory),
    baseURL: "http://secondary-user-refresh.test",
    secret: "secondary-user-refresh-fixture-secret-at-least-thirty-two-characters",
    session: { storeSessionInDatabase: true },
    verification: { storeInDatabase: true },
    telemetry: { enabled: false },
    logger: { level: "debug", log(level, message, ...args) { record({ kind: "logger", level, message, args }); } },
    secondaryStorage: {
      async get(key) {
        record({ kind: "cache.get.start", key });
        if (enabled && scenario.parallel && Object.hasOwn(gates, key)) {
          gates[key].entered.resolve();
          await gates[key].release.promise;
        }
        if (enabled && ((scenario.name.endsWith("refresh-error") && key === indexKey) || (scenario.parallel && key === "token-a"))) {
          record({ kind: "cache.get.throw", key, error: cacheFailure });
          throw cacheFailure;
        }
        const value = cache.get(key) ?? null;
        record({ kind: "cache.get.return", key, value });
        return value;
      },
      async set(key, value, ttl) {
        record({ kind: "cache.set.start", key, value, ttl });
        cache.set(key, value);
        record({ kind: "cache.set.return", key, value: undefined });
        if (key === "token-b") siblingFinished.resolve();
      },
      async delete(key) {
        record({ kind: "cache.delete.start", key });
        cache.delete(key);
        record({ kind: "cache.delete.return", key, value: undefined });
      },
    },
    databaseHooks: { user: { update: {
      before(data, context) {
        record({ kind: "hook.before", data, context });
        if (scenario.cancel) return false;
      },
      after(data, context) {
        record({ kind: "hook.after", data, context });
        if (scenario.afterError) throw afterFailure;
      },
    } } },
  };

  try {
    if (sqlite) await (await getMigrations(options)).runMigrations();
    const context = await betterAuth(options).$context;
    const seeded = await context.adapter.create({ model: "user", forceAllowId: true, data: { ...owner } });
    assert.equal(seeded.id, owner.id);
    const before = { database: databaseSnapshot(), cache: cacheSnapshot() };
    enabled = true;
    start = Date.now();

    const update = async () => {
      try {
        const value = await context.internalAdapter.updateUser(scenario.missing ? "missing-owner" : owner.id, { name: "Updated" });
        if (value) {
          assert.ok(value.updatedAt instanceof Date);
          updatedAt = value.updatedAt.toISOString();
        }
        record({ kind: "update.return", value });
        return value;
      } catch (error) {
        record({ kind: "update.throw", error });
        throw error;
      }
    };
    const operation = async () => {
      try {
        const value = scenario.transaction ? await runWithTransaction(context.adapter, async () => {
          const value = await update();
          await queueAfterTransactionHook(async () => { record({ kind: "transaction.after" }); });
          if (scenario.rollback) {
            record({ kind: "transaction.work.throw", error: rollbackFailure });
            throw rollbackFailure;
          }
          record({ kind: "transaction.work.return", value });
          return value;
        }) : await update();
        record({ kind: "operation.return", value });
        return { kind: "returned", value: snapshot(value, failures) };
      } catch (error) {
        if (error instanceof assert.AssertionError) throw error;
        assert.ok(error instanceof Error);
        record({ kind: "operation.throw", error });
        return { kind: "thrown", error: snapshot(error, failures) };
      }
    };

    const pending = operation();
    if (scenario.parallel) {
      await Promise.race([
        Promise.all(Object.values(gates).map(gate => gate.entered.promise)),
        pending.then(() => assert.fail("The update must remain pending until both token reads begin")),
      ]);
      record({ kind: "gate.release", token: "token-a" });
      gates["token-a"].release.resolve();
    }
    const outcome = await pending;
    const afterReturn = { database: databaseSnapshot(), cache: cacheSnapshot() };
    if (scenario.parallel) {
      assert.equal(outcome.kind, "returned");
      assert.deepEqual(afterReturn.cache, before.cache, "The sibling must remain blocked when the update returns");
      record({ kind: "gate.release", token: "token-b" });
      gates["token-b"].release.resolve();
      await siblingFinished.promise;
    }
    end = Date.now();
    const after = { database: databaseSnapshot(), cache: cacheSnapshot() };
    if (!updatedAt && !scenario.missing && !scenario.cancel) {
      const storedDate = after.database.user[0].updatedAt;
      updatedAt = typeof storedDate === "string" ? storedDate : storedDate.value;
    }
    if (updatedAt) {
      const milliseconds = Date.parse(updatedAt);
      assert.ok(milliseconds >= start && milliseconds <= end, "Update timestamps must come from the operation window");
    }
    for (const event of events.filter(event => event.kind === "cache.set.start")) {
      assert.equal(event.key, "token-b");
      assert.equal(typeof event.value, "string");
      const value = JSON.parse(event.value);
      assert.equal(value.session.expiresAt, expiresAt.toISOString());
      assert.equal(value.user.name, "Updated");
      assert.equal(value.user.updatedAt, updatedAt);
      assert.ok(Number.isInteger(event.ttl));
      assert.ok(event.ttl >= Math.floor((expiresAt.getTime() - end) / 1000));
      assert.ok(event.ttl <= Math.floor((expiresAt.getTime() - start) / 1000));
      event.ttl = "<validated-session-ttl>";
    }
    verifyCase(backend, scenario, before, afterReturn, after, events, outcome);
    return normalize({ backend, scenario: scenario.name, transaction: scenario.transaction, before, events, outcome, afterReturn, after }, updatedAt);
  } finally {
    for (const gate of Object.values(gates)) gate.release.resolve();
    sqlite?.close();
  }
}

function verifyCase(backend, scenario, before, afterReturn, after, events, outcome) {
  const hooks = events.filter(event => event.kind.startsWith("hook."));
  assert.deepEqual(hooks.map(event => event.kind), scenario.cancel || scenario.rollback
    ? ["hook.before"] : ["hook.before", "hook.after"]);
  for (const event of hooks) {
    assert.ok(event.context === null || event.context?.type === "undefined");
    if (event.kind === "hook.before") assert.deepEqual(event.data, { name: "Updated" });
  }
  const changed = !scenario.missing && !scenario.cancel && !scenario.rollback;
  if (!changed) assert.deepEqual(after.database, before.database);
  else {
    assert.equal(after.database.user.length, 1);
    assert.equal(after.database.user[0].name, "Updated");
    const expected = structuredClone(before.database);
    expected.user[0].name = "Updated";
    expected.user[0].updatedAt = after.database.user[0].updatedAt;
    assert.deepEqual(after.database, expected);
  }
  if (scenario.missing) assert.equal(hooks[1].data, null);
  const errorSource = scenario.afterError ? "after" : scenario.rollback ? "rollback" : null;
  assert.equal(outcome.kind, errorSource ? "thrown" : "returned");
  if (errorSource) assert.equal(outcome.error.injected, errorSource);
  else if (scenario.missing || scenario.cancel) assert.equal(outcome.value, null);
  else {
    assert.equal(outcome.value.id, owner.id);
    assert.equal(outcome.value.name, "Updated");
  }
  const logs = events.filter(event => event.kind === "logger");
  const transactionLogs = scenario.transaction ? [{
    kind: "logger", level: "debug",
    message: `[${backend === "memory" ? "Memory Adapter" : "Kysely Adapter"}] - Using provided transaction implementation.`,
    args: [],
  }] : [];
  assert.deepEqual(logs.slice(0, transactionLogs.length), transactionLogs);
  const refreshLogs = logs.slice(transactionLogs.length);
  assert.equal(refreshLogs.length, errorSource ? 0 : 1, `${backend}/${scenario.name}: ${JSON.stringify(logs)}`);
  for (const log of refreshLogs) {
    assert.equal(log.level, "error");
    assert.equal(log.message, refreshMessage);
    assert.equal(log.args.length, 1);
    const typeError = scenario.missing || scenario.cancel || scenario.malformed;
    assert.equal(log.args[0].name, typeError ? "TypeError" : "Error");
    assert.equal(log.args[0].injected, typeError ? null : "cache");
  }
  assert.equal(events.filter(event => event.kind === "transaction.after").length,
    scenario.transaction && !scenario.rollback && !scenario.afterError ? 1 : 0);
  const cacheEvents = events.filter(event => event.kind.startsWith("cache."));
  if (scenario.missing || scenario.cancel || errorSource) assert.deepEqual(cacheEvents, []);
  if (scenario.malformed) {
    assert.deepEqual(cacheEvents.filter(event => event.kind === "cache.get.start").map(event => event.key), [indexKey, "token-a"]);
    assert.deepEqual(cacheEvents.filter(event => event.kind === "cache.get.return").map(event => event.value),
      [before.cache.find(entry => entry.key === indexKey).value, "{}"]);
    assert.ok(cacheEvents.every(event => event.kind.startsWith("cache.get.")));
  }
  if (!scenario.parallel) {
    assert.deepEqual(after.cache, before.cache);
    assert.deepEqual(afterReturn, after);
  } else {
    assert.deepEqual(cacheEvents.filter(event => event.kind === "cache.get.start").map(event => event.key), [indexKey, "token-a", "token-b"]);
    assert.deepEqual(cacheEvents.filter(event => event.kind === "cache.set.start").map(event => event.key), ["token-b"]);
    assert.equal(after.cache.find(entry => entry.key === "token-a").value, before.cache.find(entry => entry.key === "token-a").value);
    assert.equal(after.cache.find(entry => entry.key === indexKey).value, before.cache.find(entry => entry.key === indexKey).value);
    const beforeB = JSON.parse(before.cache.find(entry => entry.key === "token-b").value);
    const afterB = JSON.parse(after.cache.find(entry => entry.key === "token-b").value);
    assert.deepEqual(afterB.session, beforeB.session);
    assert.deepEqual(afterB.user, JSON.parse(JSON.stringify(outcome.value, (_, value) => value?.type === "date" ? value.value : value)));
    assert.ok(events.findIndex(event => event.kind === "operation.return") < events.findIndex(event => event.kind === "cache.set.start"));
  }
}

export async function captureSecondaryUserRefresh() {
  const cases = [];
  for (const backend of ["memory", "sqlite"]) {
    for (const scenario of secondaryUserRefreshScenarios) cases.push(await captureCase(backend, scenario));
  }
  assert.equal(cases.length, 18);
  return {
    version,
    contract: {
      errors: "name, message, enumerable own properties, and injected identity; stack formatting is excluded",
      clocks: "updatedAt and TTL are checked against the operation window before normalization",
      parallel: "release token-a failure, observe the returned update, then release token-b and await its cache write",
    },
    cases,
  };
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureSecondaryUserRefresh(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
