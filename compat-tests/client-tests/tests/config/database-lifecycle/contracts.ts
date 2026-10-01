import assert from "node:assert/strict";

export type StorageMode = "database" | "cache" | "database-cache" | "preserved";
export type Control = (body: unknown) => Promise<any>;
export type Contract = { name: string; modes?: StorageMode[]; run(control: Control, mode: StorageMode): Promise<unknown> };
const databaseModes: StorageMode[] = ["database", "database-cache", "preserved"];
const cacheModes: StorageMode[] = ["cache", "database-cache", "preserved"];
const kinds = (state: any) => state.events.map((event: any) => event.kind);
const hooks = (state: any) => state.events.filter((event: any) => !event.kind.startsWith("cache.")).map((event: any) => `${event.kind}:${event.data?.id ?? "null"}`);
const live = (state: any) => state.sessions.filter((row: any) => Date.parse(row.expiresAt) > Date.now());

async function execute(control: Control, options: unknown, operation: string, patch?: unknown) {
  await control({ action: "seed" });
  await control({ action: "configure", options });
  return control({ action: "execute", operation, patch });
}

export const contracts: Contract[] = [
  {
    name: "single revocation skips a missing index and still deletes the token", modes: cacheModes,
    async run(control, mode) {
      const result = await execute(control, { missingIndex: true, failDeleteKey: "active-sessions-u1" }, "delete-session");
      assert.equal(result.ok, true);
      assert.deepEqual(result.state.cache.map((row: any) => row.key), ["s2-token"]);
      assert.deepEqual(result.state.references, []);
      assert.deepEqual(result.state.events.filter((row: any) => row.kind === "cache.delete").map((row: any) => row.data.key), ["s1-token"]);
      assert.deepEqual(hooks(result.state), mode === "cache" ? [] : ["session.delete.before:s1", "session.delete.after:s1"]);
      return result;
    },
  },
  {
    name: "single revocation preserves malformed cached snapshots and database rows", modes: cacheModes,
    async run(control, mode) {
      const result = await execute(control, { corruptSession: true }, "delete-session");
      assert.equal(result.ok, true);
      assert.equal(result.state.cache.length, 2);
      assert.equal(result.state.cache[0].session, null);
      assert.equal(live(result.state).length, mode === "cache" ? 0 : 2);
      assert.deepEqual(kinds(result.state), ["cache.get"]);
      return result;
    },
  },
  {
    name: "single token cache deletion failure propagates before database hooks", modes: cacheModes,
    async run(control, mode) {
      const result = await execute(control, { failDeleteKey: "s1-token" }, "delete-session");
      assert.equal(result.ok, false);
      assert.equal(result.state.cache.length, 2);
      assert.equal(live(result.state).length, mode === "cache" ? 0 : 2);
      assert.deepEqual(hooks(result.state), []);
      assert.equal(kinds(result.state).at(-1), "cache.delete");
      assert.deepEqual(result.state.references[0].tokens, ["s2-token"]);
      return result;
    },
  },
  {
    name: "null cached expiration and modification dates preserve the original dates", modes: ["cache"],
    async run(control) {
      const result = await execute(control, {}, "update-session", { label: "null-dates", expiresAt: null, updatedAt: null });
      assert.equal(result.ok, true);
      assert.equal(result.result.expiresAt, "2100-01-02T03:04:05.000Z");
      assert.equal(result.result.updatedAt, "2021-02-03T04:05:06.000Z");
      assert.equal(result.result.createdAt, "2020-01-02T03:04:05.000Z");
      assert.equal(result.result.label, "null-dates");
      assert.deepEqual(result.state.cache[0].session, result.result);
      assert.equal(result.state.events.at(-1).kind, "session.update.after");
      return result;
    },
  },
  {
    name: "second before failure preserves the complete batch and propagates", modes: databaseModes,
    async run(control, mode) {
      const result = await execute(control, { fail: "session.delete.before:s2" }, "delete-user-sessions");
      assert.equal(result.ok, false);
      assert.deepEqual(hooks(result.state), ["session.delete.before:s1", "session.delete.before:s2"]);
      assert.equal(live(result.state).length, 2);
      assert.equal(result.state.cache.length, mode === "database" ? 0 : 2);
      return result;
    },
  },
  {
    name: "real SQLite batch write failure occurs after every before hook and before any after hook", modes: databaseModes,
    async run(control, mode) {
      const result = await execute(control, { batchWriteFailure: true }, "delete-user-sessions");
      assert.equal(result.ok, false);
      assert.deepEqual(hooks(result.state), ["session.delete.before:s1", "session.delete.before:s2"]);
      assert.equal(live(result.state).length, 2);
      assert.equal(result.state.cache.length, mode === "database" ? 0 : 2);
      return result;
    },
  },
  {
    name: "second before cancellation preserves the complete session batch and cache", modes: databaseModes,
    async run(control, mode) {
      const result = await execute(control, { cancel: "session:s2" }, "delete-user-sessions");
      assert.equal(result.ok, true);
      assert.deepEqual(hooks(result.state), ["session.delete.before:s1", "session.delete.before:s2"]);
      assert.equal(live(result.state).length, 2);
      assert.equal(result.state.cache.length, mode === "database" ? 0 : 2);
      assert.equal(kinds(result.state).includes("cache.delete"), false);
      return result;
    },
  },
  {
    name: "after failure occurs after the complete database batch write and stops cache cleanup", modes: databaseModes,
    async run(control, mode) {
      const result = await execute(control, { fail: "session.delete.after:s1" }, "delete-user-sessions");
      assert.equal(result.ok, false);
      assert.deepEqual(hooks(result.state), ["session.delete.before:s1", "session.delete.before:s2", "session.delete.after:s1"]);
      assert.equal(live(result.state).length, 0);
      assert.equal(result.state.sessions.length, mode === "preserved" ? 2 : 0);
      assert.equal(result.state.cache.length, mode === "database" ? 0 : 2);
      return result;
    },
  },
  {
    name: "user cancellation follows child deletion and does not delete cached sessions",
    async run(control, mode) {
      const result = await execute(control, { cancel: "user:u1" }, "delete-user");
      assert.equal(result.ok, true);
      assert.deepEqual(result.state.users, ["u1"]);
      assert.deepEqual(result.state.accounts, []);
      assert.deepEqual(result.state.sessions, []);
      assert.equal(result.state.cache.length, mode === "database" ? 0 : 2);
      assert.deepEqual(hooks(result.state), [
        ...(mode === "cache" ? [] : ["session.delete.before:s1", "session.delete.before:s2", "session.delete.after:s1", "session.delete.after:s2"]),
        "account.delete.before:a1", "account.delete.before:a2", "account.delete.after:a1", "account.delete.after:a2", "user.delete.before:u1",
      ]);
      return result;
    },
  },
  {
    name: "child batch cancellation does not cancel the subsequent user deletion", modes: databaseModes,
    async run(control, mode) {
      const result = await execute(control, { cancel: "session:s2" }, "delete-user");
      assert.equal(result.ok, true);
      assert.deepEqual(result.state.users, []);
      assert.deepEqual(result.state.accounts, []);
      assert.deepEqual(result.state.sessions, []);
      assert.deepEqual(result.state.cache, []);
      assert.deepEqual(hooks(result.state), ["session.delete.before:s1", "session.delete.before:s2", "account.delete.before:a1", "account.delete.before:a2", "account.delete.after:a1", "account.delete.after:a2", "user.delete.before:u1", "user.delete.after:u1"]);
      return result;
    },
  },
  {
    name: "committed cache deletion failure is logged without failing bulk revocation", modes: cacheModes,
    async run(control, mode) {
      const result = await execute(control, { cacheFailure: "delete" }, "delete-user-sessions");
      assert.equal(result.ok, true);
      assert.equal(live(result.state).length, 0);
      assert.equal(result.state.cache.length, 2);
      assert.equal(kinds(result.state).at(-1), "cache.delete");
      return result;
    },
  },
  {
    name: "preserved bulk deletion excludes expired rows", modes: ["preserved"],
    async run(control) {
      const result = await execute(control, { expireSecond: true }, "delete-user-sessions");
      assert.equal(result.ok, true);
      assert.deepEqual(hooks(result.state), ["session.delete.before:s1", "session.delete.after:s1"]);
      assert.equal(live(result.state).length, 0);
      assert.equal(result.state.sessions.length, 2);
      const ended = result.state.sessions.find((row: any) => row.id === "s1");
      const expired = result.state.sessions.find((row: any) => row.id === "s2");
      assert.notEqual(ended.updatedAt, "2021-02-03T04:05:06.000Z");
      assert.equal(Math.abs(Date.parse(ended.updatedAt) - Date.parse(ended.expiresAt)) < 1000, true);
      assert.equal(expired.updatedAt, "2021-02-03T04:05:06.000Z");
      assert.deepEqual(result.state.cache, []);
      return result;
    },
  },
  {
    name: "single-session cancellation occurs after token cache deletion", modes: ["database-cache", "preserved"],
    async run(control) {
      const result = await execute(control, { cancel: "session:s1" }, "delete-session");
      assert.equal(result.ok, true);
      assert.deepEqual(hooks(result.state), ["session.delete.before:s1"]);
      assert.equal(live(result.state).length, 2);
      assert.deepEqual(result.state.cache.map((entry: any) => entry.key), ["s2-token"]);
      assert.deepEqual(result.state.references[0].tokens, ["s2-token"]);
      assert.equal(kinds(result.state).indexOf("cache.delete") < kinds(result.state).indexOf("session.delete.before"), true);
      return result;
    },
  },
  {
    name: "update cancellation happens before both cache and database writes",
    async run(control, mode) {
      const result = await execute(control, { cancel: "session.update" }, "update-session");
      assert.equal(result.ok, true);
      assert.equal(result.result, null);
      assert.deepEqual(kinds(result.state), ["session.update.before"]);
      if (mode !== "cache") assert.equal(result.state.sessions[0].label, "s1-old");
      if (mode !== "database") assert.equal(result.state.cache[0].session.label, "s1-old");
      return result;
    },
  },
  {
    name: "hook patch precedes cache write and database output precedes after hook", modes: cacheModes,
    async run(control, mode) {
      const result = await execute(control, { patch: { label: "hook", token: "changed-token", createdAt: "2010-01-01T00:00:00.000Z", updatedAt: "2022-01-01T00:00:00.000Z" } }, "update-session");
      assert.equal(result.ok, true);
      const writes = result.state.events.filter((event: any) => event.kind === "cache.set");
      assert.deepEqual(writes.map((event: any) => event.data.key), ["s1-token", "active-sessions-u1"]);
      assert.equal(result.state.events[0].kind, "session.update.before");
      assert.deepEqual(result.state.events[0].data, { label: "request" });
      assert.equal(result.state.events.at(-1).kind, "session.update.after");
      if (mode !== "cache") assert.equal(writes[0].databaseSessions[0].label, "s1-old");
      const cached = result.state.cache.find((entry: any) => entry.key === "s1-token").session;
      assert.equal(cached.label, "hook");
      assert.equal(cached.token, "changed-token");
      assert.equal(cached.createdAt, "2020-01-02T03:04:05.000Z");
      assert.deepEqual(result.state.references[0].tokens, ["s1-token", "s2-token"]);
      assert.equal(result.result.createdAt, mode === "cache" ? cached.createdAt : "2010-01-01T00:00:00.000Z");
      return result;
    },
  },
  {
    name: "cache update failure prevents database update and after hook", modes: cacheModes,
    async run(control, mode) {
      const result = await execute(control, { cacheFailure: "set" }, "update-session");
      assert.equal(result.ok, false);
      assert.equal(kinds(result.state).includes("session.update.after"), false);
      assert.equal(result.state.cache[0].session.label, "s1-old");
      if (mode !== "cache") assert.equal(result.state.sessions[0].label, "s1-old");
      return result;
    },
  },
  {
    name: "database update failure leaves the preceding cache write committed", modes: ["database-cache", "preserved"],
    async run(control) {
      const result = await execute(control, { databaseUpdateFailure: true }, "update-session");
      assert.equal(result.ok, false);
      assert.equal(result.state.cache[0].session.label, "request");
      assert.equal(result.state.sessions[0].label, "s1-old");
      assert.equal(kinds(result.state).includes("session.update.after"), false);
      return result;
    },
  },
  {
    name: "after update failure preserves the completed writes",
    async run(control, mode) {
      const result = await execute(control, { fail: "session.update.after" }, "update-session");
      assert.equal(result.ok, false);
      assert.equal(result.state.events.at(-1).kind, "session.update.after");
      if (mode !== "cache") assert.equal(result.state.sessions[0].label, "request");
      if (mode !== "database") {
        assert.equal(result.state.cache[0].session.label, "request");
        assert.equal(result.state.cache[0].session.updatedAt, "2021-02-03T04:05:06.000Z");
      }
      return result;
    },
  },
  {
    name: "missing storage result still reaches after update as null", modes: cacheModes,
    async run(control, mode) {
      const result = await execute(control, mode === "cache" ? { evictCache: true } : { deleteDatabaseSession: true }, "update-session");
      assert.equal(result.ok, true);
      assert.equal(result.result, null);
      assert.equal(result.state.events.at(-1).kind, "session.update.after");
      assert.equal(result.state.events.at(-1).data, null);
      if (mode !== "cache") assert.equal(result.state.cache[0].session.label, "request");
      return result;
    },
  },
];
