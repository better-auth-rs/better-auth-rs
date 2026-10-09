import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { getWithHooks } from "../node_modules/better-auth/dist/db/with-hooks.mjs";

type Backend = "memory" | "sqlite";
type Path = "create" | "find" | "update" | "delete";
type Fields = Record<string, unknown>;
const date = (offset: number) => new Date(1_893_456_000_000 + offset * 1000);
const row = (id = "target", accountId = "subject", accessToken = "before") => ({
  id, accountId, providerId: "provider", userId: "owner", accessToken,
  refreshToken: "refresh", idToken: "id-token", accessTokenExpiresAt: date(10),
  refreshTokenExpiresAt: date(20), scope: "read", password: "password",
  createdAt: date(0), updatedAt: date(0),
});

async function setup(backend: Backend) {
  const memory: Record<string, Fields[]> = { user: [], account: [], session: [], verification: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options: BetterAuthOptions = {
    database: sqlite ?? memoryAdapter(memory),
    baseURL: "http://account-live-output.test",
    secret: "account-live-output-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
  };
  if (sqlite) await (await getMigrations(options)).runMigrations();
  const writer = await betterAuth(options).$context;
  await writer.adapter.create({ model: "user", forceAllowId: true, data: {
    id: "owner", name: "Owner", email: "owner@account-live-output.test", emailVerified: true,
    image: null, createdAt: date(0), updatedAt: date(0),
  } });
  return {
    options, writer,
    storage: () => sqlite ? sqlite.query("SELECT * FROM account ORDER BY id").all() : memory.account,
    stored: (value: Fields) => sqlite
      ? Object.fromEntries(Object.entries(value).map(([key, value]) => [key, value instanceof Date ? value.toISOString() : value]))
      : value,
    close: () => sqlite?.close(),
  };
}

async function check(backend: Backend, path: Path, reject: boolean, duplicate = false) {
  const fixture = await setup(backend);
  try {
    const events: unknown[] = [];
    const failure = new TypeError("account-output-rejected");
    const original = row();
    const retained = row("retained", "retained-subject", "retained");
    const second = row("target", "duplicate-subject", "second-before");
    const outer = { ...original, scope: path === "update" ? "requested" : "read" };
    const changed = { ...outer, accessToken: "after", updatedAt: date(1) };
    const secondChanged = { ...second, scope: outer.scope, accessToken: "after", updatedAt: date(1) };
    const hooks = { account: {
      create: { after(value: unknown) { events.push(["after-create", value]); } },
      update: { after(value: unknown) { events.push(["after-update", value]); } },
      delete: {
        before(value: unknown) { events.push(["before-delete", value]); },
        after(value: unknown) { events.push(["after-delete", value]); },
      },
    } };
    const options: BetterAuthOptions = {
      ...fixture.options,
      account: { additionalFields: {
        accountId: { type: "string", transform: { async output(value) {
          events.push(["accountId", value]);
          if (duplicate) events.push(["before-write", structuredClone(fixture.storage())]);
          const written = await fixture.writer.adapter.update({ model: "account", where: [{ field: "id", value: "target" }], update: {
            accessToken: "after", updatedAt: date(1),
          } });
          events.push(["write", written]);
          if (reject) throw failure;
          return value;
        } } },
        accessToken: { type: "string", transform: { output(value) {
          events.push(["accessToken", value]);
          return `${value}:out`;
        } } },
      } },
    };
    const reader = await betterAuth(options).$context;
    const withHooks = getWithHooks(reader.adapter, { options, hooks: [{ source: "user", hooks }] });
    const seed = (data: Fields) => fixture.writer.adapter.create({ model: "account", data, forceAllowId: true });
    await seed(retained);
    if (path !== "create") await seed(original);
    if (duplicate) await seed(second);
    const operation = () => path === "create"
      ? withHooks.createWithHooks(original, "account")
      : path === "find"
        ? reader.adapter.findMany({ model: "account", limit: 2, where: [
          { field: "providerId", value: "provider" }, { field: "accountId", value: "subject" },
        ] }).then(rows => rows[0])
        : path === "update"
          ? withHooks.updateWithHooks({ accessToken: "before", scope: "requested", updatedAt: date(0) }, [{ field: "id", value: "target" }], "account")
          : withHooks.deleteWithHooks([{ field: "id", value: "target" }], "account");
    const trace: unknown[] = [["accountId", "subject"]];
    if (duplicate) trace.push(["before-write", [
      retained, outer, path === "update" ? { ...second, accessToken: "before", scope: "requested" } : second,
    ]]);
    trace.push(["write", changed]);
    if (reject) {
      if (path === "delete") {
        expect(await operation()).toBeNull();
      } else {
        let caught: unknown;
        try { await operation(); } catch (error) { caught = error; }
        expect(caught).toBe(failure);
      }
    } else {
      const accessToken = backend === "memory" ? "after" : "before";
      const projected = { ...(backend === "memory" ? changed : outer), accessToken: `${accessToken}:out` };
      if (path === "delete") expect(await operation()).toBeUndefined();
      else expect(await operation()).toStrictEqual(projected);
      trace.push(["accessToken", accessToken]);
      if (path === "delete") trace.push(["before-delete", projected], ["after-delete", projected]);
      else if (path !== "find") trace.push([`after-${path}`, projected]);
    }
    expect(events).toStrictEqual(trace);
    expect(fixture.storage()).toStrictEqual([
      fixture.stored(retained),
      ...(path === "delete" && !reject ? [] : [fixture.stored(changed), ...(duplicate ? [secondChanged] : [])]),
    ]);
  } finally { fixture.close(); }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const path of ["create", "find", "update", "delete"] as const) {
    for (const reject of [false, true]) {
      test(`${backend} Account ${path} output ${reject ? "retains callback writes and failure behavior" : "reads the adapter record source"}`, async () => {
        await check(backend, path, reject);
      });
    }
  }
}

for (const path of ["update", "delete"] as const) {
  for (const reject of [false, true]) {
    test(`memory Account duplicate ID ${path} ${reject ? "retains callback writes and failure behavior" : "writes every match and projects only the first"}`, async () => {
      await check("memory", path, reject, true);
    });
  }
}
