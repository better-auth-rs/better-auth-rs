import assert from "node:assert/strict";

type Mode = "database" | "cache" | "database-cache" | "preserved";
type Control = (body: unknown) => Promise<any>;
const allModes: Mode[] = ["database", "cache", "database-cache", "preserved"];
const databaseModes: Mode[] = ["database", "database-cache", "preserved"];
const cacheModes: Mode[] = ["cache", "database-cache", "preserved"];
const hooks = (state: any) => state.events.filter((event: any) => !event.kind.startsWith("cache.")).map((event: any) => `${event.kind}:${event.data?.id ?? "null"}`);
const cacheDeletes = (state: any) => state.events.filter((event: any) => event.kind === "cache.delete").map((event: any) => event.data.key);
const live = (state: any) => state.sessions.filter((row: any) => Date.parse(row.expiresAt) > Date.now());

async function run(control: Control, options: unknown, tokens = ["s1-token", "s2-token"]) {
  await control({ action: "seed" });
  await control({ action: "configure", options });
  return control({ action: "execute", operation: "delete-sessions", tokens });
}

function unchangedIndex(state: any, mode: Mode) {
  assert.deepEqual(state.references, mode === "database" ? [] : [{ key: "active-sessions-u1", tokens: ["s1-token", "s2-token"] }]);
}

export const tokenListContracts = [
  {
    name: "token-list deletion clears tokens before one database batch and retains the index",
    modes: allModes,
    async run(control: Control, mode: Mode) {
      const result = await run(control, {});
      assert.equal(result.ok, true);
      assert.equal(result.state.cache.length, 0);
      assert.equal(live(result.state).length, 0);
      unchangedIndex(result.state, mode);
      assert.deepEqual(cacheDeletes(result.state), mode === "database" ? [] : ["s1-token", "s2-token"]);
      assert.deepEqual(hooks(result.state), mode === "cache" ? [] : ["session.delete.before:s1", "session.delete.before:s2", "session.delete.after:s1", "session.delete.after:s2"]);
      if (mode !== "database") assert.deepEqual(result.state.events.slice(0, 2).map((event: any) => event.kind), ["cache.delete", "cache.delete"]);
      return result;
    },
  },
  ...[
    { name: "cancellation", options: { cancel: "session:s2" }, ok: true, live: 2, after: false },
    { name: "before failure", options: { fail: "session.delete.before:s2" }, ok: false, live: 2, after: false },
    { name: "write failure", options: { batchWriteFailure: true }, ok: false, live: 2, after: false },
    { name: "after failure", options: { fail: "session.delete.after:s1" }, ok: false, live: 0, after: true },
  ].map(example => ({
    name: `token-list ${example.name} preserves the cache-before-database boundary`,
    modes: databaseModes,
    async run(control: Control, mode: Mode) {
      const result = await run(control, example.options);
      assert.equal(result.ok, example.ok);
      assert.equal(result.state.cache.length, 0);
      assert.equal(live(result.state).length, example.live);
      unchangedIndex(result.state, mode);
      assert.deepEqual(hooks(result.state), ["session.delete.before:s1", "session.delete.before:s2", ...(example.after ? ["session.delete.after:s1"] : [])]);
      return result;
    },
  })),
  {
    name: "token-list cache failure keeps the database untouched and permits peer deletion",
    modes: cacheModes,
    async run(control: Control, mode: Mode) {
      const result = await run(control, { failDeleteKey: "s1-token" });
      assert.equal(result.ok, false);
      assert.deepEqual(cacheDeletes(result.state), ["s1-token", "s2-token"]);
      assert.deepEqual(result.state.cache.map((row: any) => row.key), ["s1-token"]);
      assert.deepEqual(hooks(result.state), []);
      assert.equal(live(result.state).length, mode === "cache" ? 0 : 2);
      unchangedIndex(result.state, mode);
      return result;
    },
  },
  {
    name: "duplicate tokens repeat cache calls but identify each database row once",
    modes: allModes,
    async run(control: Control, mode: Mode) {
      const result = await run(control, {}, ["s1-token", "s1-token", "unknown-token"]);
      assert.equal(result.ok, true);
      assert.deepEqual(cacheDeletes(result.state), mode === "database" ? [] : ["s1-token", "s1-token", "unknown-token"]);
      assert.deepEqual(hooks(result.state), mode === "cache" ? [] : ["session.delete.before:s1", "session.delete.after:s1"]);
      assert.equal(live(result.state).length, mode === "cache" ? 0 : 1);
      unchangedIndex(result.state, mode);
      return result;
    },
  },
  {
    name: "empty token lists preserve rows, cache tokens, and indices without hooks",
    modes: allModes,
    async run(control: Control, mode: Mode) {
      const result = await run(control, {}, []);
      assert.equal(result.ok, true);
      assert.deepEqual(result.state.events, []);
      assert.equal(live(result.state).length, mode === "cache" ? 0 : 2);
      assert.equal(result.state.cache.length, mode === "database" ? 0 : 2);
      unchangedIndex(result.state, mode);
      return result;
    },
  },
  {
    name: "preserved token batches expire live rows and leave expired rows unchanged",
    modes: ["preserved"] as Mode[],
    async run(control: Control, mode: Mode) {
      const result = await run(control, { expireSecond: true });
      assert.equal(result.ok, true);
      assert.equal(live(result.state).length, 0);
      assert.equal(result.state.cache.length, 0);
      assert.deepEqual(hooks(result.state), ["session.delete.before:s1", "session.delete.after:s1"]);
      assert.equal(result.state.sessions[1].expiresAt, "2000-01-01T00:00:00.000Z");
      assert.equal(result.state.sessions[1].updatedAt, "2021-02-03T04:05:06.000Z");
      unchangedIndex(result.state, mode);
      return result;
    },
  },
  {
    name: "one cache rejection returns while a blocked peer remains alive until release",
    modes: cacheModes,
    async run(control: Control, mode: Mode) {
      const rejected = await run(control, { failDeleteKey: "s1-token", holdDeleteKey: "s2-token" });
      assert.equal(rejected.ok, false);
      assert.deepEqual(cacheDeletes(rejected.state), ["s1-token", "s2-token"]);
      assert.equal(rejected.state.cache.length, 2);
      assert.deepEqual(hooks(rejected.state), []);
      assert.equal(live(rejected.state).length, mode === "cache" ? 0 : 2);
      unchangedIndex(rejected.state, mode);
      const released = await control({ action: "release-delete" });
      assert.deepEqual(released.state.cache.map((row: any) => row.key), ["s1-token"]);
      assert.deepEqual(hooks(released.state), []);
      assert.equal(live(released.state).length, mode === "cache" ? 0 : 2);
      unchangedIndex(released.state, mode);
      return { rejected, released };
    },
  },
];
