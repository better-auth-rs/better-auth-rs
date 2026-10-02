import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { deviceAuthorization } from "better-auth/plugins";

const base = {
  baseURL: "http://device-fields.test",
  secret: "ordinary-device-extra-fields-secret-at-least-32-characters",
  logger: { disabled: true },
  telemetry: { enabled: false },
};
const aliases = {
  settings: "stored_settings",
  nullableSettings: "stored_nullable_settings",
  tags: "stored_tags",
  targets: "stored_targets",
  targetNumbers: "stored_target_numbers",
  targetDocument: "stored_target_document",
} as const;
type Field = keyof typeof aliases;
const names = Object.keys(aliases) as Field[];
type Row = Record<string, any>;

const display = (row: Row) => Object.fromEntries(names.map((name) => {
  assert.ok(Object.hasOwn(row, name), `Expected declared field ${name}`);
  return [name, row[name]];
}));
const native = (row: Row) => {
  const result = { ...row };
  for (const name of names) {
    delete result[name];
    delete result[aliases[name]];
  }
  return result;
};
const storedPhysical = (memory: Record<string, Row[]>, code: string) => {
  const row = memory.deviceCode.find((row) => row.deviceCode === code);
  assert.ok(row, "Expected the stored ordinary Device row");
  return Object.fromEntries(names.map((name) => {
    const alias = aliases[name];
    assert.ok(Object.hasOwn(row, alias), `Expected physical field ${alias}`);
    return [alias, row[alias]];
  }));
};
const input = (label: string, targets: string[]) => ({
  deviceCode: `ordinary-device:${label}`, userCode: `ordinary-user:${label}`,
  userId: null, expiresAt: new Date("2030-01-01T00:00:00Z"), status: "pending",
  lastPolledAt: null, pollingInterval: 5000, clientId: "ordinary-client", scope: "read",
  settings: { theme: "dark" }, nullableSettings: null, tags: ["alpha", "beta"],
  targets, targetNumbers: targets.map(Number), targetDocument: targets,
});

export async function captureDeviceMemoryRepresentation() {
  const cases = [];
  for (const mode of ["custom", "serial"] as const) {
    const memory: Record<string, Row[]> = { user: [], session: [], account: [], verification: [], deviceCode: [] };
    let nextId = 1;
    const generateId = mode === "serial" ? "serial" as const : () => String(nextId++);
    const database = memoryAdapter(memory);
    const options = { ...base, database, advanced: { database: { generateId } } };
    const reader = (await betterAuth({ ...options, plugins: [deviceAuthorization()] }).$context).adapter;
    const targets: string[] = [];
    for (const index of [1, 2]) {
      const user = await reader.create<any>({ model: "user", data: {
        name: `Display target ${index}`, email: `target${index}@device-fields.test`, emailVerified: false,
        createdAt: new Date("2030-01-01T00:00:00Z"), updatedAt: new Date("2030-01-01T00:00:00Z"),
      } });
      targets.push(user.id);
    }
    assert.deepEqual(targets, ["1", "2"]);

    const events: unknown[] = [];
    const transform = (name: Field) => ({
      input(value: unknown) {
        assert.notEqual(value, undefined, `Expected supplied input field ${name}`);
        events.push(["input", name, value]);
        return value;
      },
      output(value: unknown) {
        assert.notEqual(value, undefined, `Expected stored output field ${name}`);
        events.push(["output", name, value]);
        return value;
      },
    });
    const reference = { model: "user", field: "id" };
    const fields = {
      settings: { type: "json" as const, required: false, fieldName: aliases.settings, transform: transform("settings") },
      nullableSettings: { type: "json" as const, required: false, fieldName: aliases.nullableSettings, transform: transform("nullableSettings") },
      tags: { type: "string[]" as const, required: false, fieldName: aliases.tags, transform: transform("tags") },
      targets: { type: "string[]" as const, required: false, fieldName: aliases.targets, references: reference, transform: transform("targets") },
      targetNumbers: { type: "number[]" as const, required: false, fieldName: aliases.targetNumbers, references: reference, transform: transform("targetNumbers") },
      targetDocument: { type: "json" as const, required: false, fieldName: aliases.targetDocument, references: reference, transform: transform("targetDocument") },
    };
    const writer = (await betterAuth({ ...options, plugins: [
      deviceAuthorization(), { id: "ordinary-device-memory-representation", schema: { deviceCode: { fields } } },
    ] }).$context).adapter;
    const takeEvents = () => events.splice(0);
    const label = `representation-${mode}`;
    const created = await writer.create<any>({ model: "deviceCode", data: input(label, targets) });
    const expectedNative = native(created);
    const byDevice = [{ field: "deviceCode", value: created.deviceCode }];
    const byId = [{ field: "id", value: created.id }];
    const observe = async (name: string, result: unknown) => {
      const stored = await reader.findOne<any>({ model: "deviceCode", where: byDevice });
      assert.ok(stored, "Expected the ordinary Device row through the native reader");
      assert.deepEqual(native(stored), expectedNative);
      return { name, events: takeEvents(), result, storedPhysical: storedPhysical(memory, created.deviceCode), nativeUnchanged: true };
    };
    const operations = [await observe("create", display(created))];
    for (const name of ["read-device", "read-user", "update", "update-if-status", "read-after-status"] as const) {
      let result: unknown;
      if (name === "update-if-status") {
        const updated = await writer.update<any>({ model: "deviceCode", where: [...byId, { field: "status", value: "pending" }], update: { settings: { theme: "guarded" } } });
        result = updated !== null;
      } else {
        const row = name === "update"
          ? await writer.update<any>({ model: "deviceCode", where: byId, update: { settings: { theme: "light" } } })
          : await writer.findOne<any>({ model: "deviceCode", where: name === "read-user" ? [{ field: "userCode", value: created.userCode }] : byDevice });
        assert.ok(row, "Expected the ordinary Device operation result");
        assert.deepEqual(native(row), expectedNative);
        result = display(row);
      }
      operations.push(await observe(name, result));
    }

    const transaction = await writer.transaction(async (tx) => {
      const created = await tx.create<any>({ model: "deviceCode", data: input(`${label}-transaction`, targets) });
      const expectedNative = native(created);
      const operations = [{ name: "create", events: takeEvents(), result: display(created), nativeUnchanged: true }];
      const read = await tx.findOne<any>({ model: "deviceCode", where: [{ field: "deviceCode", value: created.deviceCode }] });
      assert.ok(read, "Expected the transaction to read its Device row");
      assert.deepEqual(native(read), expectedNative);
      operations.push({ name: "read-device", events: takeEvents(), result: display(read), nativeUnchanged: true });
      const updated = await tx.update<any>({ model: "deviceCode", where: [{ field: "id", value: created.id }], update: { settings: { theme: "transaction" } } });
      assert.ok(updated, "Expected the transaction to update its Device row");
      assert.deepEqual(native(updated), expectedNative);
      operations.push({ name: "update", events: takeEvents(), result: display(updated), nativeUnchanged: true });
      return { operations, expectedNative, deviceCode: created.deviceCode };
    });
    // The native reader preserves the adapter's public ID representation after commit.
    const committed = await reader.findOne<any>({ model: "deviceCode", where: [{ field: "deviceCode", value: transaction.deviceCode }] });
    assert.ok(committed, "Expected the committed ordinary Device row");
    assert.deepEqual(native(committed), transaction.expectedNative);
    assert.deepEqual(takeEvents(), []);
    cases.push({ mode, operations, transaction: {
      operations: transaction.operations,
      storedPhysical: storedPhysical(memory, transaction.deviceCode),
      nativeUnchanged: true,
    } });
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureDeviceMemoryRepresentation(), null, 2));
