import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

type Fields = Record<string, unknown>;
type Declaration = NonNullable<NonNullable<BetterAuthOptions["verification"]>["additionalFields"]>;
const date = (offset: number) => new Date(1_893_456_000_000 + offset * 1000);
const values = (id: string, identifier: unknown, value: string, created = 0, expires: unknown = date(100)) => ({
  id, identifier, value, createdAt: date(created), expiresAt: expires, updatedAt: date(0),
});

async function setup(backend: "memory" | "sqlite", fields: Declaration, generateId?: NonNullable<NonNullable<BetterAuthOptions["advanced"]>["database"]>["generateId"], integerId = false) {
  const memory: Record<string, Fields[]> = { user: [], account: [], session: [], verification: [] };
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  // Keep the physical schema fixed while declarations replace native types and field mappings.
  database?.exec(`CREATE TABLE verification (id ${integerId ? "INTEGER" : "TEXT"} PRIMARY KEY NOT NULL, identifier TEXT NOT NULL, value TEXT NOT NULL, expiresAt TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL)`);
  const options: BetterAuthOptions = {
    database: database ?? memoryAdapter(memory), baseURL: "http://verification-fields.test",
    secret: "verification-field-query-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    verification: { additionalFields: fields },
    advanced: { database: { generateId } },
  };
  const context = await betterAuth(options).$context;
  return {
    ...context,
    raw: () => structuredClone(database ? database.query("SELECT * FROM verification ORDER BY id").all() as Fields[] : memory.verification),
    close: () => database?.close(),
  };
}

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} verification replacements select mapped fields through CRUD and atomic consumption`, async () => {
    const context = await setup(backend, {
      identifier: { type: "string", fieldName: "value" },
      value: { type: "string", fieldName: "identifier" },
      createdAt: { type: "date", fieldName: "expiresAt" },
      expiresAt: { type: "date", fieldName: "createdAt" },
    });
    const where = (field: string, value: string) => [{ field, value }];
    const create = (data: Fields) => context.adapter.create<Fields>({ model: "verification", data, forceAllowId: true });
    try {
      const first = await create(values("first", "subject", "proof", 1));
      expect(first).toStrictEqual(values("first", "subject", "proof", 1));
      for (const [field, value] of [["identifier", "subject"], ["value", "proof"], ["id", "first"]]) {
        expect(await context.adapter.findOne({ model: "verification", where: where(field, value) })).toStrictEqual(first);
      }
      const changed = { ...first, value: "new-proof", updatedAt: date(3) };
      expect(await context.adapter.update({ model: "verification", where: where("identifier", "subject"), update: { value: "new-proof", updatedAt: date(3) } })).toStrictEqual(changed);
      const storage = { id: "first", identifier: "new-proof", value: "subject", createdAt: date(100), expiresAt: date(1), updatedAt: date(3) };
      expect(context.raw()).toStrictEqual([backend === "memory" ? storage : { ...storage, createdAt: date(100).toISOString(), expiresAt: date(1).toISOString(), updatedAt: date(3).toISOString() }]);
      await context.adapter.delete({ model: "verification", where: where("identifier", "subject") });
      expect(context.raw()).toStrictEqual([]);
      await create(values("old", "shared", "old-proof", 1, date(500)));
      const latest = await create(values("new", "shared", "latest-proof", 2));
      expect(await context.adapter.findMany({ model: "verification", where: where("identifier", "shared"), sortBy: { field: "createdAt", direction: "desc" }, limit: 1 })).toStrictEqual([latest]);
      const consumed = await Promise.all(Array.from({ length: 8 }, () => context.internalAdapter.consumeVerificationValue("shared")));
      expect(consumed.filter(value => value !== null)).toStrictEqual([latest]);
      expect(context.raw()).toStrictEqual([]);
      await create(values("expired", "expired", "proof", 1, date(-1_000_000_000)));
      expect(await context.adapter.deleteMany({ model: "verification", where: [{ field: "expiresAt", operator: "lt", value: new Date() }] })).toBe(1);
      expect(context.raw()).toStrictEqual([]);
    } finally { context.close(); }
  });

  test(`${backend} verification query types and ID references preserve dynamic output`, async () => {
    for (const [type, value, query, reference] of [
      ["number", 16, "0x10", false], ["boolean", true, "true", false], ["string", "0x10", "1.6e1", true],
    ] as const) {
      let calls = 0;
      const context = await setup(backend, {
        identifier: { type, ...(reference ? { references: { model: "user", field: "id" } } : {}), transform: { input(value) { calls++; return value; } } },
        expiresAt: { type: "string" },
      }, reference ? "serial" : undefined);
      try {
        const created = await context.adapter.create<Fields>({ model: "verification", data: values("41", value, "payload", 0, "not-a-date"), forceAllowId: true });
        expect(created.expiresAt).toBe("not-a-date");
        expect(calls).toBe(1);
        expect(await context.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: query }] })).toStrictEqual(created);
        expect(calls).toBe(1);
        expect(await context.internalAdapter.consumeVerificationValue(query)).toStrictEqual(created);
        expect(calls).toBe(1);
        expect(context.raw()).toStrictEqual([]);
      } finally { context.close(); }
    }
  });

  test(`${backend} verification ID aliases retain declaration order and input failures`, async () => {
    for (const idFirst of [false, true]) {
      for (const reject of [false, true]) {
        const events: string[] = [];
        const id = { type: "string" as const, fieldName: "ignored", transform: {
          input() { throw new Error("configured-id-input-called"); }, output() { throw new Error("configured-id-output-called"); },
        } };
        const shadow = { type: "string" as const, fieldName: "id", transform: {
          input(value: unknown) { events.push("input"); if (reject) throw new Error("verification-input-rejected"); return value; },
          output(value: unknown) { events.push("output"); return value; },
        } };
        const context = await setup(backend, idFirst ? { id, shadow } : { shadow, id }, () => { events.push("generate"); return "generated"; });
        try {
          const { id: _, ...data } = values("unused", "subject", "payload");
          const create = context.adapter.create<Fields>({ model: "verification", data: { ...data, shadow: "shadow-id" } });
          if (reject) {
            await expect(create).rejects.toThrow("verification-input-rejected");
            expect(events).toStrictEqual(idFirst ? ["generate", "input"] : ["input"]);
            expect(context.raw()).toStrictEqual([]);
          } else {
            const result = await create;
            const expected = idFirst ? "shadow-id" : "generated";
            expect(result).toStrictEqual({ ...data, id: expected, shadow: expected });
            expect(events).toStrictEqual(idFirst ? ["generate", "input", "output"] : ["input", "generate", "output"]);
            expect(context.raw()).toStrictEqual([backend === "memory" ? { ...data, id: expected } : { ...data, id: expected, createdAt: date(0).toISOString(), expiresAt: date(100).toISOString(), updatedAt: date(0).toISOString() }]);
          }
        } finally { context.close(); }
      }
    }
  });
}


test("sqlite verification ID aliases defer integer primary-key coercion to the database", async () => {
  const context = await setup("sqlite", {
    value: { type: "string", transform: { input() { return 43; } } },
    id: { type: "string" },
    idAlias: { type: "string", fieldName: "id" },
  }, "serial", true);
  try {
    const { id: _, ...data } = values("unused", "runtime-verification", "input-value");
    const created = await context.adapter.create<Fields>({ model: "verification", data: { ...data, idAlias: "1.0" } });
    const expected = { ...data, value: "43", id: "1", idAlias: "1" };
    expect(created).toStrictEqual(expected);
    expect(context.raw()).toStrictEqual([{
      ...data, id: 1, value: "43", createdAt: date(0).toISOString(), updatedAt: date(0).toISOString(), expiresAt: date(100).toISOString(),
    }]);
    expect(await context.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: "runtime-verification" }] })).toStrictEqual(expected);
  } finally { context.close(); }
});

test("memory verification update changes every match before projecting the first row", async () => {
  for (const reject of [false, true]) {
    const events: string[] = [];
    let rejectOutput = false;
    const context = await setup("memory", {
      identifier: { type: "string", fieldName: "value" },
      value: { type: "string", fieldName: "identifier", transform: {
        input(value) { events.push("input"); return value; },
        output(value) { events.push("output"); if (rejectOutput) throw new Error("verification-output-rejected"); return value; },
      } },
      createdAt: { type: "date", fieldName: "expiresAt" },
      expiresAt: { type: "date", fieldName: "createdAt" },
    });
    try {
      const create = (data: Fields) => context.adapter.create<Fields>({ model: "verification", data, forceAllowId: true });
      const first = await create(values("first", "shared", "first-proof", 1));
      const second = await create(values("second", "shared", "second-proof", 2));
      const retained = await create(values("retained", "other", "retained-proof", 3));
      const expectedFirst = { ...first, value: "new-proof", updatedAt: date(3) };
      const expectedSecond = { ...second, value: "new-proof", updatedAt: date(3) };
      events.length = 0;
      rejectOutput = reject;
      const updated = context.internalAdapter.updateVerificationByIdentifier("shared", { value: "new-proof", updatedAt: date(3) });
      if (reject) await expect(updated).rejects.toThrow("verification-output-rejected");
      else expect(await updated).toStrictEqual(expectedFirst);
      expect(events).toStrictEqual(["input", "output"]);
      rejectOutput = false;
      expect(await context.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: "shared" }] })).toStrictEqual(expectedFirst);
      expect(await context.adapter.findMany({ model: "verification", where: [{ field: "identifier", value: "shared" }], sortBy: { field: "createdAt", direction: "desc" }, limit: 1 })).toStrictEqual([expectedSecond]);
      expect(await context.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: "other" }] })).toStrictEqual(retained);
      expect(context.raw()).toStrictEqual([
        { id: "first", identifier: "new-proof", value: "shared", createdAt: date(100), expiresAt: date(1), updatedAt: date(3) },
        { id: "second", identifier: "new-proof", value: "shared", createdAt: date(100), expiresAt: date(2), updatedAt: date(3) },
        { id: "retained", identifier: "retained-proof", value: "other", createdAt: date(100), expiresAt: date(3), updatedAt: date(0) },
      ]);
    } finally { context.close(); }
  }
});

test("memory verification latest and consume place null below a negative number", async () => {
  const events: string[] = [];
  const context = await setup("memory", {
    identifier: { type: "string", fieldName: "value" },
    value: { type: "string", fieldName: "identifier" },
    createdAt: { type: "number", fieldName: "expiresAt", transform: { output(value) { events.push("output"); return value; } } },
    expiresAt: { type: "date", fieldName: "createdAt" },
  });
  try {
    const create = (data: Fields) => context.adapter.create<Fields>({ model: "verification", data, forceAllowId: true });
    await create({ ...values("null", "shared", "null-proof"), createdAt: null });
    const latest = await create({ ...values("negative", "shared", "negative-proof"), createdAt: -1 });
    const retained = await create(values("retained", "other", "retained-proof", 3));
    events.length = 0;
    expect(await context.adapter.findMany({ model: "verification", where: [{ field: "identifier", value: "shared" }], sortBy: { field: "createdAt", direction: "desc" }, limit: 1 })).toStrictEqual([latest]);
    expect(events).toStrictEqual(["output"]);
    events.length = 0;
    const consumed = await Promise.all(Array.from({ length: 8 }, () => context.internalAdapter.consumeVerificationValue("shared")));
    expect(consumed.filter(value => value !== null)).toStrictEqual([latest]);
    expect(events).toStrictEqual(["output", "output"]);
    expect(await context.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: "shared" }] })).toBeNull();
    expect(await context.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: "other" }] })).toStrictEqual(retained);
    expect(context.raw()).toStrictEqual([
      { id: "retained", identifier: "retained-proof", value: "other", createdAt: date(100), expiresAt: date(3), updatedAt: date(0) },
    ]);
  } finally { context.close(); }
});
