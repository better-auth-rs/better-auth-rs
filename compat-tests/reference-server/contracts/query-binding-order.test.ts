import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { deviceAuthorization, organization } from "better-auth/plugins";
import { walletPlugin } from "./wallet-additional-fields";

const date = (offset: number) => new Date(1_893_456_000_000 + offset * 1000);

for (const generateId of ["serial", false] as const) {
  test(`SQLite User ID queries preserve driver comparisons with generateId=${generateId}`, async () => {
    const database = new Database(":memory:");
    try {
      database.exec(`CREATE TABLE user (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, emailVerified INTEGER NOT NULL, image TEXT, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL);
        INSERT INTO user VALUES (0, 'Zero', 'zero@query-binding-order.test', 0, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'),
          (16, 'Owner', 'owner@query-binding-order.test', 1, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z');`);
      const raw = () => database.query("SELECT * FROM user ORDER BY id").all();
      const before = raw();
      const { adapter } = await betterAuth({
        database, baseURL: "http://query-binding-order.test",
        secret: "query-binding-order-contract-at-least-32-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        advanced: { database: { generateId } },
      }).$context;
      const read = (value: string) => adapter.findOne({ model: "user", where: [{ field: "id", value }] });
      const owner = {
        id: "16", name: "Owner", email: "owner@query-binding-order.test", emailVerified: true,
        image: null, createdAt: date(0), updatedAt: date(0),
      };
      expect(await read("invalid")).toBeNull();
      expect(await read("1.5")).toBeNull();
      expect(await read("1.6e1")).toStrictEqual(owner);
      expect(await read("16")).toStrictEqual(owner);
      expect(await read("0x10")).toStrictEqual(generateId === "serial" ? owner : null);
      expect(await read("")).toStrictEqual(generateId === "serial" ? {
        id: "0", name: "Zero", email: "zero@query-binding-order.test", emailVerified: false,
        image: null, createdAt: date(0), updatedAt: date(0),
      } : null);
      expect(raw()).toStrictEqual(before);
    } finally {
      database.close();
    }
  });
}

for (const rejectedInput of [false, true]) {
  test(`SQLite User input ${rejectedInput ? "failure precedes" : "runs before"} the second query binding`, async () => {
    const database = new Database(":memory:");
    try {
      // Adapter writes or reads would replace the application ID declaration before this update.
      database.exec(`CREATE TABLE user (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, emailVerified INTEGER NOT NULL, image TEXT, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL);
        INSERT INTO user VALUES ('seed', 'Before', 'seed@example.test', 1, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z');`);
      const raw = () => database.query("SELECT * FROM user ORDER BY id").all() as Record<string, unknown>[];
      const before = raw();
      const events: string[] = [];
      let reject = rejectedInput;
      const options: BetterAuthOptions = {
        database, baseURL: "http://query-binding-order.test",
        secret: "query-binding-order-contract-at-least-32-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        user: { additionalFields: {
          name: { type: "string", transform: {
            input(value) {
              events.push("name-input");
              if (reject) throw new Error("user-input-rejected");
              return value;
            },
            output(value) { events.push("name-output"); return value; },
          } },
          image: { type: "string", defaultValue() {
            events.push("image-default");
            return "creation-only-image";
          } },
          updatedAt: { type: "date", onUpdate() {
            events.push("updated-on-update");
            return date(1);
          }, transform: { input(value) {
            events.push("updated-input");
            expect(value).toStrictEqual(date(1));
            return value;
          } } },
          id: { type: "string", fieldName: "old_id" },
        } },
      };
      const { adapter } = await betterAuth(options).$context;
      expect(events).toStrictEqual([]);
      const update = () => adapter.update({ model: "user", where: [{ field: "id", value: "seed" }], update: { name: "After" } });
      let failure: unknown;
      try { await update(); } catch (error) { failure = error; }
      if (!(failure instanceof Error)) throw new Error("The first User update must fail");
      expect({ name: failure.name, message: failure.message }).toStrictEqual(rejectedInput
        ? { name: "Error", message: "user-input-rejected" }
        : { name: "BetterAuthError", message: "Field old_id not found in model user" });
      expect(events).toStrictEqual(rejectedInput ? ["name-input"] : ["name-input", "updated-on-update", "updated-input"]);
      expect(raw()).toStrictEqual(before);

      reject = false;
      events.length = 0;
      expect(await update()).toStrictEqual({
        id: "seed", name: "After", email: "seed@example.test", emailVerified: true,
        image: null, createdAt: date(0), updatedAt: date(1),
      });
      expect(events).toStrictEqual(["name-input", "updated-on-update", "updated-input", "name-output"]);
      expect(raw()).toStrictEqual(before.map(row => ({ ...row, name: "After", updatedAt: date(1).toISOString() })));
    } finally {
      database.close();
    }
  });
}

const base = {
  baseURL: "http://query-binding-order.test",
  secret: "query-binding-order-contract-at-least-32-characters",
  logger: { disabled: true }, telemetry: { enabled: false },
};

for (const invalidOwnership of [false, true]) {
  test(`SQLite Device consumption ${invalidOwnership ? "operand error precedes" : "resolves"} the first ID alias`, async () => {
    const database = new Database(":memory:");
    try {
      database.exec(`CREATE TABLE deviceCode (id TEXT PRIMARY KEY NOT NULL, deviceCode TEXT NOT NULL, userCode TEXT NOT NULL, userId TEXT, expiresAt TEXT NOT NULL, status TEXT NOT NULL, lastPolledAt TEXT, pollingInterval INTEGER, clientId TEXT, scope TEXT);
        INSERT INTO deviceCode VALUES ('1', 'target-device', 'ABCD2345', 'owner', '2030-01-01T00:00:00.000Z', 'approved', NULL, NULL, 'client', '7'),
          ('2', 'retained-device', 'EFGH2345', 'owner', '2030-01-01T00:00:00.000Z', 'approved', NULL, NULL, 'client', '9');`);
      const raw = () => database.query("SELECT * FROM deviceCode ORDER BY id").all() as Record<string, unknown>[];
      const before = raw();
      const events: string[] = [];
      const options: BetterAuthOptions = {
        ...base, database,
        advanced: { database: { generateId: "serial" } },
        plugins: [deviceAuthorization(), { id: "device-query-binding-order", schema: { deviceCode: { fields: {
          id: { type: "string", fieldName: "old_id" },
          scope: { type: "string", references: { model: "user", field: "id" }, transform: {
            input(value) { events.push("scope-input"); return value; },
            output(value) { events.push("scope-output"); return value; },
          } },
        } } } }],
      };
      const { adapter } = await betterAuth(options).$context;
      // The native object tests Number conversion before the adapter resolves any SQL field aliases.
      const consume = (value: unknown) => Reflect.apply(adapter.consumeOne, adapter, [{
        model: "deviceCode", where: [
          { field: "id", value: "1" }, { field: "scope", value }, { field: "status", value: "approved" },
        ],
      }]);
      let failure: unknown;
      try { await consume(invalidOwnership ? { toString: null } : "7"); } catch (error) { failure = error; }
      if (!(failure instanceof Error)) throw new Error("The first Device consumption must fail");
      expect({ name: failure.name, message: failure.message }).toStrictEqual(invalidOwnership
        ? { name: "TypeError", message: "No default value" }
        : { name: "BetterAuthError", message: "Field old_id not found in model deviceCode" });
      expect(events).toStrictEqual([]);
      expect(raw()).toStrictEqual(before);

      expect(await consume("7")).toStrictEqual({
        id: "1", deviceCode: "target-device", userCode: "ABCD2345", userId: "owner",
        expiresAt: date(0), status: "approved", lastPolledAt: null, pollingInterval: null, clientId: "client", scope: "7",
      });
      expect(events).toStrictEqual(["scope-output"]);
      expect(raw()).toStrictEqual(before.filter(row => row.id === "2"));
    } finally {
      database.close();
    }
  });
}

test("SQLite Wallet mixed aliases resolve twice without converting operands twice", async () => {
  const database = new Database(":memory:");
  try {
    database.exec(`CREATE TABLE walletAddress (id TEXT PRIMARY KEY NOT NULL, userId TEXT NOT NULL, address TEXT NOT NULL, chainId INTEGER NOT NULL, isPrimary INTEGER NOT NULL, createdAt TEXT NOT NULL);
      INSERT INTO walletAddress VALUES ('mixed', 'owner', 'true', 1, 0, '2030-01-01T00:00:00.000Z'),
        ('converted-twice', 'owner', '1', 1, 0, '2030-01-01T00:00:00.000Z');`);
    const raw = () => database.query("SELECT * FROM walletAddress ORDER BY id").all();
    const before = raw();
    const events: string[] = [];
    const options: BetterAuthOptions = {
      ...base, database,
      plugins: [walletPlugin(), { id: "wallet-query-binding-order", schema: { walletAddress: { fields: {
        address: { type: "string", fieldName: "chainId", transform: {
          input(value) { events.push("address-input"); return value; },
          output(value) { events.push("address-output"); return value; },
        } },
        chainId: { type: "boolean", fieldName: "address", transform: {
          input(value) { events.push("chain-input"); return value; },
          output(value) { events.push("chain-output"); return value; },
        } },
      } } } }],
    };
    const { adapter } = await betterAuth(options).$context;
    expect(await adapter.findOne({ model: "walletAddress", where: [
      { field: "address", value: "true" }, { field: "chainId", value: "true" },
    ] })).toStrictEqual({
      id: "mixed", userId: "owner", address: 1, chainId: "true", isPrimary: false, createdAt: date(0),
    });
    expect(events).toStrictEqual(["address-output", "chain-output"]);
    expect(raw()).toStrictEqual(before);
  } finally {
    database.close();
  }
});

test("SQLite OrganizationRole names convert as one array and keep the organization filter", async () => {
  const database = new Database(":memory:");
  try {
    database.exec(`CREATE TABLE organizationRole (id TEXT PRIMARY KEY NOT NULL, organizationId TEXT NOT NULL, role TEXT NOT NULL, permission TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT);
      INSERT INTO organizationRole VALUES ('numeric-name', 'target-org', '01', '{}', '2030-01-01T00:00:00.000Z', NULL),
        ('text-name', 'target-org', 'literal', '{}', '2030-01-01T00:00:00.000Z', NULL),
        ('converted-name', 'target-org', '1', '{}', '2030-01-01T00:00:00.000Z', NULL),
        ('other-tenant', 'other-org', '01', '{}', '2030-01-01T00:00:00.000Z', NULL);`);
    const raw = () => database.query("SELECT * FROM organizationRole ORDER BY id").all();
    const before = raw();
    const events: string[] = [];
    const options: BetterAuthOptions = {
      ...base, database,
      plugins: [organization({ dynamicAccessControl: { enabled: true } }), {
        id: "organization-role-query-binding-order", schema: { organizationRole: { fields: {
          role: { type: "number", transform: {
            input(value) { events.push("role-input"); return value; },
            output(value) { events.push("role-output"); return value; },
          } },
        } } },
      }],
    };
    const { adapter } = await betterAuth(options).$context;
    const query = (names: string[]) => adapter.findMany({ model: "organizationRole", where: [
      { field: "organizationId", value: "target-org" }, { field: "role", operator: "in", value: names },
    ] });
    // Number conversion preserves the whole array when any name is not numeric.
    expect(await query(["01", "literal"])).toStrictEqual([
      { id: "numeric-name", organizationId: "target-org", role: "01", permission: "{}", createdAt: date(0), updatedAt: null },
      { id: "text-name", organizationId: "target-org", role: "literal", permission: "{}", createdAt: date(0), updatedAt: null },
    ]);
    expect(events).toStrictEqual(["role-output", "role-output"]);
    expect(raw()).toStrictEqual(before);
    events.length = 0;
    expect(await query([])).toStrictEqual([]);
    expect(events).toStrictEqual([]);
    expect(raw()).toStrictEqual(before);
  } finally {
    database.close();
  }
});
