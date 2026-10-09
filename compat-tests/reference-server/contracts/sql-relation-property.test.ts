import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import type { DBFieldAttribute } from "@better-auth/core/db";

type Row = Record<string, unknown>;
type Target = "account" | "user" | "session";
const date = "2030-01-01T00:00:00.000Z";
const changed = "2030-01-01T00:00:01.000Z";
const collision = "stored-parent-property";
const user = (id: string, name: string): Row => ({ id, name, email: `${id}@sql-relation-property.test`, emailVerified: 1, image: null, createdAt: date, updatedAt: date });
const account = (id: string, accessToken: string, userId: string): Row => ({
  id, accountId: id, providerId: "provider", userId, accessToken, refreshToken: "refresh",
  idToken: "id-token", accessTokenExpiresAt: date, refreshTokenExpiresAt: date,
  scope: "read", password: "password", createdAt: date, updatedAt: date,
});
const session = (): Row => ({ id: "parent", token: "existing-token", userId: "child",
  expiresAt: "2100-01-01T00:00:00.000Z", ipAddress: "127.0.0.1", userAgent: "native-sql-contract", createdAt: date, updatedAt: date });
function projected(row: Row): Row {
  return Object.fromEntries(Object.entries(row).map(([name, value]) => [name,
    ["createdAt", "updatedAt", "expiresAt", "accessTokenExpiresAt", "refreshTokenExpiresAt"].includes(name)
      ? new Date(value as string) : name === "emailVerified" ? !!value : value,
  ]));
}

async function check(target: Target, joins: boolean, reject: boolean, missing: boolean) {
  const database = new Database(":memory:");
  try {
    const many = target === "user";
    const child = many ? "account" : "user";
    const physical = `linked_${child}`;
    const parentTable = target === "session" ? "session" : `linked_${target}`;
    const valueField = many ? "accessToken" : "name";
    const fields: Record<string, DBFieldAttribute> = {
      [physical]: { type: "string" },
      relationMirror: { type: "string", fieldName: physical },
    };
    const options: BetterAuthOptions = {
      database, baseURL: "http://sql-relation-property.test",
      secret: "native-sql-relation-property-contract-secret-at-least-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      advanced: { database: { joins } },
      user: { modelName: "linked_user", ...(target === "user" ? { additionalFields: fields } : {}) },
      account: { modelName: "linked_account", ...(target === "account" ? { additionalFields: fields } : {}) },
      session: target === "session" ? { additionalFields: fields } : {},
    };
    await (await getMigrations(options)).runMigrations();
    // The empty-child case represents persisted rows whose referenced record no longer exists.
    database.exec("PRAGMA foreign_keys = OFF");
    const insert = (table: string, row: Row) => {
      const fields = Object.keys(row);
      database.query(`INSERT INTO "${table}" (${fields.map(name => `"${name}"`).join(",")}) VALUES (${fields.map(() => "?").join(",")})`).run(...Object.values(row) as (string | number | null)[]);
    };
    const parent = { ...(many ? user("parent", "Parent") : target === "session" ? session() : account("parent", "Parent", "child")), [physical]: collision };
    const children = missing ? [] : many ? [account("child", "Before", "parent"), account("second", "Second", "parent")] : [user("child", "Before")];
    insert(parentTable, parent);
    for (const row of children) insert(physical, row);
    const storage = (table: string) => database.query(`SELECT * FROM "${table}" ORDER BY id`).all();
    const beforeParent = storage(parentTable);
    const beforeChildren = storage(physical) as Row[];
    const joined = (rows: Row[]) => many ? rows : rows[0] ?? null;
    const raw = joins ? joined(children) : collision;
    const events: unknown[][] = [];
    let captured: unknown;
    const failure = new TypeError("raw-relation-output-rejected");
    const parentFields: Record<string, DBFieldAttribute> = {
      [physical]: { type: "string", transform: { output(value) {
        expect(value).toStrictEqual(raw);
        captured = value;
        events.push(["collision", structuredClone(value)]);
        if (!missing) {
          database.query(`UPDATE "${physical}" SET "${valueField}"=?, "updatedAt"=? WHERE id=?`).run("After", changed, "child");
          expect(value).toStrictEqual(raw);
          events.push(["after-write", structuredClone(value)]);
        }
        if (reject) throw failure;
        return value;
      } } },
      relationMirror: { type: "string", fieldName: physical, transform: { output(value) {
        expect(value).toBe(captured);
        expect(value).toStrictEqual(raw);
        events.push(["mirror", structuredClone(value)]);
        return value;
      } } },
    };
    const childFields: Record<string, DBFieldAttribute> = {
      [valueField]: { type: "string", transform: { output(value) {
        events.push(["child", value]);
        return `visible:${value}`;
      } } },
    };
    const reader = (await betterAuth({
      ...options,
      user: { ...options.user, additionalFields: many ? parentFields : childFields },
      account: { ...options.account, additionalFields: many ? childFields : target === "account" ? parentFields : {} },
      session: target === "session" ? { additionalFields: parentFields } : {},
    }).$context).adapter;
    const operation = () => reader.findOne({ model: target, where: [{ field: "id", value: "parent" }], join: { [child]: true } });
    const expectedEvents: unknown[][] = [["collision", raw], ...(!missing ? [["after-write", raw]] : [])];
    if (reject) {
      let caught: unknown;
      try { await operation(); } catch (error) { caught = error; }
      expect(caught).toBe(failure);
    } else {
      const output = await operation();
      expectedEvents.push(["mirror", raw]);
      const visible = children.map((row, index) => {
        const selected = !joins && index === 0 ? { ...row, [valueField]: "After", updatedAt: changed } : row;
        expectedEvents.push(["child", selected[valueField]]);
        return projected({ ...selected, [valueField]: `visible:${selected[valueField]}` });
      });
      expect(output).toStrictEqual({ ...projected(parent), [physical]: raw, relationMirror: raw, [child]: joined(visible) });
      expect(output?.[physical]).toBe(captured);
      expect(output?.relationMirror).toBe(captured);
    }
    expect(events).toStrictEqual(expectedEvents);
    expect(storage(parentTable)).toStrictEqual(beforeParent);
    expect(storage(physical)).toStrictEqual(beforeChildren.map(row => row.id === "child" ? { ...row, [valueField]: "After", updatedAt: changed } : row));
  } finally { database.close(); }
}

for (const target of ["account", "user", "session"] as const) {
  for (const joins of [false, true]) for (const reject of [false, true]) {
    test(`SQLite ${target} raw relation snapshot joins=${joins}, reject=${reject}`, () => check(target, joins, reject, false));
  }
  test(`SQLite ${target} empty raw relation replaces the parent collision`, () => check(target, true, false, true));
}
