import { expect, test } from "bun:test";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { organization } from "better-auth/plugins";

type Row = Record<string, unknown>;
type Event = { kind: "input" | "output"; value: unknown };

const createdAt = new Date("2030-01-01T00:00:00.000Z");

async function adapter(
  database: Record<string, Row[]>,
  model: string,
  fields: Record<string, DBFieldAttribute> = {},
  serial = false,
) {
  return (await betterAuth({
    database: memoryAdapter(database),
    baseURL: "http://organization-native-binding.test",
    secret: "organization-native-binding-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: serial ? "serial" : undefined } },
    plugins: [
      organization({ dynamicAccessControl: { enabled: true } }),
      { id: "organization-native-binding", schema: { [model]: { fields } } },
    ],
  }).$context).adapter;
}

function observedField(field: DBFieldAttribute, events: Event[]): DBFieldAttribute {
  return { ...field, transform: {
    input(value) {
      events.push({ kind: "input", value });
      throw new Error("query-input-must-not-run");
    },
    output(value) {
      events.push({ kind: "output", value });
      return value;
    },
  } };
}

function members(alias: boolean): Row[] {
  const values = alias ? [1, 1, "01"] : [1, 1, "01", " ", 0, "literal", true, true, false, false, "true", "false", "anything"];
  return values.map((value, index) => ({
    id: `m${index}`, organizationId: alias ? "untouched" : value,
    userId: "owner", role: alias ? value : "member", createdAt,
  }));
}

type MemberCase = {
  name: string;
  field: DBFieldAttribute;
  value: unknown;
  matched: number[];
  alias?: boolean;
  serial?: boolean;
  fails?: boolean;
};

const memberCases: MemberCase[] = [
  { name: "Number numeric text", field: { type: "number" }, value: "01", matched: [0, 1] },
  { name: "Number whitespace", field: { type: "number" }, value: " ", matched: [3] },
  { name: "Number literal", field: { type: "number" }, value: "literal", matched: [5] },
  { name: "Boolean true text", field: { type: "boolean" }, value: "true", matched: [6, 7] },
  { name: "Boolean false text", field: { type: "boolean" }, value: "false", matched: [8, 9] },
  { name: "Boolean other text", field: { type: "boolean" }, value: "anything", matched: [8, 9] },
  { name: "Number physical alias", field: { type: "number", fieldName: "role" }, value: "01", matched: [0, 1], alias: true },
  ...[
    { name: "numeric text", value: "01", matched: [0, 1] },
    { name: "Boolean text", value: "true", matched: [] },
    { name: "native object", value: { toString: null }, matched: [], fails: true },
  ].map(value => ({
    ...value, name: `Serial Boolean reference ${value.name}`, serial: true,
    field: { type: "boolean", references: { model: "organization", field: "id" } } satisfies DBFieldAttribute,
  })),
];

for (const scenario of memberCases) {
  test(`Memory Member query binding: ${scenario.name}`, async () => {
    const database: Record<string, Row[]> = { member: [] };
    const rows = members(scenario.alias ?? false);
    const writer = await adapter(database, "member");
    for (const data of rows) await writer.create({ model: "member", forceAllowId: true, data });
    expect(database.member).toStrictEqual(rows);
    const before = structuredClone(database.member);
    const events: Event[] = [];
    const reader = await adapter(database, "member", {
      organizationId: observedField(scenario.field, events),
    }, scenario.serial);
    const rawField = scenario.alias ? "role" : "organizationId";
    const selected = scenario.matched.map(index => rows[index]!);
    const expected = selected.map(row => ({
      ...row, organizationId: scenario.serial ? String(row[rawField]) : row[rawField],
    }));
    const outputEvents = selected.map(row => ({ kind: "output", value: row[rawField] }));
    const where = [{ field: "organizationId", value: scenario.value }];
    const operations = [
      { run: () => Reflect.apply(reader.findMany, reader, [{ model: "member", where }]), expected, events: outputEvents },
      { run: () => Reflect.apply(reader.count, reader, [{ model: "member", where }]), expected: selected.length, events: [] },
      { run: async () => ({
        members: await Reflect.apply(reader.findMany, reader, [{
          model: "member", where, limit: 1, offset: 0, sortBy: { field: "createdAt", direction: "asc" },
        }]),
        total: await Reflect.apply(reader.count, reader, [{ model: "member", where }]),
      }), expected: { members: expected.slice(0, 1), total: selected.length }, events: outputEvents.slice(0, 1) },
    ];
    for (const operation of operations) {
      if (scenario.fails) {
        const result = operation.run();
        await expect(result).rejects.toBeInstanceOf(TypeError);
        await expect(result).rejects.toMatchObject({ name: "TypeError", message: "No default value" });
      } else expect(await operation.run()).toStrictEqual(operation.expected);
      expect(events.splice(0)).toStrictEqual(operation.events);
      expect(database.member).toStrictEqual(before);
    }
  });
}

function roles(): Row[] {
  return [
    ["target-org", "01"], ["target-org", "literal"], ["target-org", 1], ["target-org", 2],
    ["target-org", "02"], ["other-org", "01"], ["other-org", 1],
  ].map(([organizationId, role], index) => ({
    id: `r${index}`, organizationId, role, permission: "{}", createdAt, updatedAt: null,
  }));
}

for (const scenario of [
  { name: "mixed names stay native", names: ["01", "literal"], matched: [0, 1] },
  { name: "all numeric names convert together", names: ["01", "02"], matched: [2, 3] },
]) {
  test(`Memory OrganizationRole query binding: ${scenario.name}`, async () => {
    const database: Record<string, Row[]> = { organizationRole: [] };
    const rows = roles();
    const writer = await adapter(database, "organizationRole");
    for (const data of rows) await writer.create({ model: "organizationRole", forceAllowId: true, data });
    expect(database.organizationRole).toStrictEqual(rows);
    const before = structuredClone(database.organizationRole);
    const events: Event[] = [];
    const reader = await adapter(database, "organizationRole", {
      role: observedField({ type: "number" }, events),
    });
    const expected = scenario.matched.map(index => rows[index]!);
    expect(await reader.findMany({ model: "organizationRole", where: [
      { field: "organizationId", value: "target-org" }, { field: "role", operator: "in", value: scenario.names },
    ] })).toStrictEqual(expected);
    expect(events.splice(0)).toStrictEqual(expected.map(row => ({ kind: "output", value: row.role })));
    expect(database.organizationRole).toStrictEqual(before);
    expect(await reader.count({ model: "organizationRole", where: [{ field: "organizationId", value: "target-org" }] })).toBe(5);
    expect(events).toStrictEqual([]);
    expect(database.organizationRole).toStrictEqual(before);
  });
}

for (const nonempty of [false, true]) {
  test(`Memory OrganizationRole JSON names validate during row evaluation: ${nonempty ? "nonempty" : "empty"}`, async () => {
    const database: Record<string, Row[]> = { organizationRole: [] };
    const rows = nonempty ? [{ ...roles()[5]!, id: "r0", role: "reader" }] : [];
    const writer = await adapter(database, "organizationRole");
    for (const data of rows) await writer.create({ model: "organizationRole", forceAllowId: true, data });
    expect(database.organizationRole).toStrictEqual(rows);
    const before = structuredClone(database.organizationRole);
    const events: Event[] = [];
    const reader = await adapter(database, "organizationRole", {
      role: observedField({ type: "json" }, events),
    });
    const result = reader.findMany({ model: "organizationRole", where: [
      { field: "organizationId", value: "target-org" }, { field: "role", operator: "in", value: ["reader"] },
    ] });
    if (nonempty) {
      await expect(result).rejects.toBeInstanceOf(Error);
      await expect(result).rejects.toMatchObject({ name: "Error", message: "Value must be an array" });
    } else expect(await result).toStrictEqual([]);
    expect(events).toStrictEqual([]);
    expect(database.organizationRole).toStrictEqual(before);
    expect(await reader.count({ model: "organizationRole", where: [{ field: "organizationId", value: "target-org" }] })).toBe(0);
    expect(events).toStrictEqual([]);
    expect(database.organizationRole).toStrictEqual(before);
  });
}
