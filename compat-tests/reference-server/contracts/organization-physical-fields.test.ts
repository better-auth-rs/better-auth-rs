import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { organization } from "better-auth/plugins";

type Row = Record<string, unknown>;
type Fields = Record<string, { type: "string"; fieldName: string }>;

const models = [
  ["organization", "name", "slug"],
  ["member", "role", "userId"],
  ["invitation", "status", "role"],
  ["team", "name", "organizationId"],
  ["organizationRole", "role", "organizationId"],
] as const;

async function adapter(database: Record<string, Row[]>, model: string, fields: Fields = {}) {
  return (await betterAuth({
    database: memoryAdapter(database),
    baseURL: "http://organization-physical.test",
    secret: "organization-physical-fields-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, logger: { disabled: true },
    plugins: [
      organization({ teams: { enabled: true }, dynamicAccessControl: { enabled: true } }),
      { id: "physical-fields", schema: { [model]: { fields } } },
    ],
  }).$context).adapter;
}

function data(model: string): Row {
  const createdAt = new Date("2025-01-01T00:00:00.000Z");
  const values: Record<string, Row> = {
    organization: { name: "name-before", slug: "slug-before" },
    member: { organizationId: "organization", userId: "recipient-before", role: "member" },
    invitation: {
      organizationId: "organization", email: "recipient@example.com", role: "member",
      status: "pending", inviterId: "inviter", teamId: null,
      expiresAt: new Date("2099-01-01T00:00:00.000Z"),
    },
    team: { name: "name-before", organizationId: "organization", memberCount: 0 },
    organizationRole: { organizationId: "organization", role: "reader", permission: "{}" },
  };
  return { id: "physical-row", createdAt, ...values[model] };
}

for (const [model, primary, alternate] of models) {
  test(`${model} reconfiguration reads existing physical columns and preserves earlier values`, async () => {
    const database: Record<string, Row[]> = {};
    const original = await adapter(database, model);
    await original.create({ model, forceAllowId: true, data: data(model) });
    const before = structuredClone(database[model]![0]!);
    const changed = await adapter(database, model, {
      [primary]: { type: "string", fieldName: alternate },
      original: { type: "string", fieldName: primary },
    });
    const where = [{ field: "id", value: "physical-row" }];
    const selected = await changed.findOne<Row>({ model, where });
    expect(selected?.[primary]).toStrictEqual(before[alternate]);
    expect(selected?.original).toStrictEqual(before[primary]);
    expect(database[model]![0]).toStrictEqual(before);
    const updated = await changed.update<Row>({ model, where, update: { [primary]: "accepted" } });
    expect(updated?.[primary]).toBe("accepted");
    expect(updated?.original).toStrictEqual(before[primary]);
    expect(database[model]![0]![primary]).toStrictEqual(before[primary]);
    expect(database[model]![0]![alternate]).toBe("accepted");
    expect(Object.hasOwn(database[model]![0]!, "original")).toBe(false);
    const physical = structuredClone(database[model]![0]!);
    const restored = await original.findOne<Row>({ model, where });
    expect(restored?.[primary]).toStrictEqual(before[primary]);
    expect(restored?.[alternate]).toBe("accepted");
    expect(database[model]![0]).toStrictEqual(physical);
  });

  test(`${model} native and additional aliases share one stored property`, async () => {
    const database: Record<string, Row[]> = {};
    const mapped = await adapter(database, model, {
      [primary]: { type: "string", fieldName: "shared" },
      shadow: { type: "string", fieldName: "shared" },
    });
    const created = await mapped.create<Row>({
      model, forceAllowId: true, data: { ...data(model), shadow: "last-writer" },
    });
    expect(created[primary]).toBe("last-writer");
    expect(created.shadow).toBe("last-writer");
    expect(database[model]![0]!.shared).toBe("last-writer");
    expect(Object.hasOwn(database[model]![0]!, primary)).toBe(false);
    expect(Object.hasOwn(database[model]![0]!, "shadow")).toBe(false);
    const where = [{ field: "id", value: "physical-row" }];
    const updated = await mapped.update<Row>({ model, where, update: { [primary]: "accepted" } });
    expect(updated?.[primary]).toBe("accepted");
    expect(updated?.shadow).toBe("accepted");
    const physical = structuredClone(database[model]![0]!);
    const restored = await (await adapter(database, model)).findOne<Row>({ model, where });
    expect(restored?.[primary]).toBeUndefined();
    expect(database[model]![0]).toStrictEqual(physical);
  });
}
