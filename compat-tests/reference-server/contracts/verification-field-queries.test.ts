import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

type Fields = Record<string, unknown>;
type Declaration = NonNullable<NonNullable<BetterAuthOptions["verification"]>["additionalFields"]>;
const date = (offset: number) => new Date(1_893_456_000_000 + offset * 1000);
const values = (id: string, identifier: unknown, value: string, created = 0, expires: unknown = date(100)) => ({
  id, identifier, value, createdAt: date(created), expiresAt: expires, updatedAt: date(0),
});

async function setup(backend: "memory" | "sqlite", fields: Declaration, generateId?: NonNullable<NonNullable<BetterAuthOptions["advanced"]>["database"]>["generateId"], integerId = false) {
  const memory: Record<string, Fields[]> = { user: [], account: [], session: [], verification: [] };
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options: BetterAuthOptions = {
    database: database ?? memoryAdapter(memory), baseURL: "http://verification-fields.test",
    secret: "verification-field-query-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    verification: { additionalFields: fields },
    advanced: { database: { generateId } },
  };
  if (database) {
    await (await getMigrations({ ...options, verification: undefined })).runMigrations();
    // Preserve the fixed Verification columns while supplying every table required by transaction schema validation.
    database.exec(`DROP TABLE verification;
      CREATE TABLE verification (id ${integerId ? "INTEGER" : "TEXT"} PRIMARY KEY NOT NULL, identifier TEXT NOT NULL, value TEXT NOT NULL, expiresAt TEXT NOT NULL, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL)`);
  }
  const context = await betterAuth(options).$context;
  return {
    ...context, options,
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
    const storedDate = (offset: number) => backend === "sqlite" ? date(offset).toISOString() : date(offset);
    try {
      const first = await create(values("first", "subject", "proof", 1));
      expect(first).toStrictEqual(values("first", "subject", "proof", 1));
      const firstStorage = { id: "first", identifier: "proof", value: "subject", createdAt: storedDate(100), expiresAt: storedDate(1), updatedAt: storedDate(0) };
      expect(context.raw()).toStrictEqual([firstStorage]);
      for (const [field, value] of [["identifier", "subject"], ["value", "proof"], ["id", "first"]]) {
        expect(await context.adapter.findOne({ model: "verification", where: where(field, value) }))
          .toStrictEqual(backend === "sqlite" && field !== "id" ? null : first);
      }
      // Kysely resolves WHERE aliases twice; storage writes and sortBy resolve aliases once.
      const identifierQuery = backend === "sqlite" ? "proof" : "subject";
      const valueQuery = backend === "sqlite" ? "subject" : "proof";
      for (const [field, value] of [["identifier", identifierQuery], ["value", valueQuery]]) {
        expect(await context.adapter.findOne({ model: "verification", where: where(field, value) })).toStrictEqual(first);
      }
      const changed = { ...first, value: "new-proof", updatedAt: date(3) };
      const update = { value: "new-proof", updatedAt: date(3) };
      if (backend === "sqlite") {
        expect(await context.adapter.update({ model: "verification", where: where("identifier", "subject"), update })).toBeNull();
        expect(context.raw()).toStrictEqual([firstStorage]);
      }
      expect(await context.adapter.update({ model: "verification", where: where("identifier", identifierQuery), update })).toStrictEqual(changed);
      const changedStorage = { ...firstStorage, identifier: "new-proof", updatedAt: storedDate(3) };
      expect(context.raw()).toStrictEqual([changedStorage]);
      const updatedIdentifier = backend === "sqlite" ? "new-proof" : "subject";
      const updatedValue = backend === "sqlite" ? "subject" : "new-proof";
      expect(await context.adapter.findOne({ model: "verification", where: [...where("identifier", updatedIdentifier), ...where("value", updatedValue)] })).toStrictEqual(changed);
      if (backend === "sqlite") {
        await context.adapter.delete({ model: "verification", where: where("identifier", "subject") });
        expect(context.raw()).toStrictEqual([changedStorage]);
      }
      await context.adapter.delete({ model: "verification", where: where("identifier", updatedIdentifier) });
      expect(context.raw()).toStrictEqual([]);

      await create(values("expired", "expired", "expired-proof", -1_000_000_000, date(-1_000_000_000)));
      const retained = await create(values("retained", "other", "retained-proof", 1));
      const retainedStorage = { id: "retained", identifier: "retained-proof", value: "other", createdAt: storedDate(100), expiresAt: storedDate(1), updatedAt: storedDate(0) };
      expect(await context.adapter.deleteMany({ model: "verification", where: [{ field: "expiresAt", operator: "lt", value: new Date() }] })).toBe(1);
      expect(context.raw()).toStrictEqual([retainedStorage]);

      const old = await create(values("old", "shared", "old-proof", 1, date(500)));
      const latest = await create(values("new", "shared", "latest-proof", 2));
      const oldStorage = { id: "old", identifier: "old-proof", value: "shared", createdAt: storedDate(500), expiresAt: storedDate(1), updatedAt: storedDate(0) };
      const latestStorage = { id: "new", identifier: "latest-proof", value: "shared", createdAt: storedDate(100), expiresAt: storedDate(2), updatedAt: storedDate(0) };
      expect(await context.adapter.findMany({ model: "verification", where: where("identifier", "shared"), sortBy: { field: "createdAt", direction: "desc" }, limit: 1 }))
        .toStrictEqual(backend === "sqlite" ? [] : [latest]);
      expect(await context.adapter.findMany({ model: "verification", where: where(backend === "sqlite" ? "value" : "identifier", "shared"), sortBy: { field: "createdAt", direction: "desc" }, limit: 1 })).toStrictEqual([latest]);
      const consumed = await Promise.all(Array.from({ length: 8 }, () => context.internalAdapter.consumeVerificationValue("shared")));
      if (backend === "sqlite") {
        expect(consumed).toStrictEqual(Array.from({ length: 8 }, () => null));
        expect(context.raw()).toStrictEqual([latestStorage, oldStorage, retainedStorage]);
        const claimed = await Promise.all(Array.from({ length: 8 }, () => context.internalAdapter.consumeVerificationValue("latest-proof")));
        expect(claimed.filter(value => value !== null)).toStrictEqual([latest]);
        expect(await context.adapter.findOne({ model: "verification", where: where("identifier", "old-proof") })).toStrictEqual(old);
        expect(await context.adapter.findOne({ model: "verification", where: where("identifier", "latest-proof") })).toBeNull();
        expect(context.raw()).toStrictEqual([oldStorage, retainedStorage]);
      } else {
        expect(consumed.filter(value => value !== null)).toStrictEqual([latest]);
        expect(context.raw()).toStrictEqual([retainedStorage]);
      }
      expect(await context.adapter.findOne({ model: "verification", where: where("identifier", "shared") })).toBeNull();
      expect(await context.adapter.findOne({ model: "verification", where: where("id", "retained") })).toStrictEqual(retained);
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

const reservationId = (identifier: string) => createHash("sha256").update(`reserve:${identifier}`).digest("base64url");
const reservationDates: Declaration = {
  createdAt: { type: "date", transform: { input() { return date(0); } } },
  updatedAt: { type: "date", transform: { input() { return date(0); } } },
};
const reservationStorage = (backend: "memory" | "sqlite", value: Fields) => backend === "memory" ? value : {
  ...value,
  createdAt: (value.createdAt as Date).toISOString(),
  updatedAt: (value.updatedAt as Date).toISOString(),
  expiresAt: (value.expiresAt as Date).toISOString(),
};

for (const backend of ["memory", "sqlite"] as const) {
  for (const serial of [false, true]) {
    test(`${backend} Verification reservation ${serial ? "Serial" : "default"} uses the adapter primary-key behavior`, async () => {
      const events: unknown[] = [];
      const context = await setup(backend, {
        ...reservationDates,
        value: { type: "string", transform: {
          input(value) { events.push(["input", value]); return value; },
          output(value) { events.push(["output", value]); return value; },
        } },
      }, serial ? "serial" : undefined, serial);
      try {
        const reserve = (value: string) => context.internalAdapter.reserveVerificationValue({ identifier: "subject", value, expiresAt: date(100) });
        const duplicate = backend === "sqlite" && !serial;
        expect([await reserve("first"), await reserve("second")]).toStrictEqual([true, !duplicate]);
        expect(events).toStrictEqual([
          ["input", "first"], ["output", "first"],
          ["input", "second"], ["output", duplicate ? "first" : "second"],
        ]);
        const first = { ...values(reservationId("subject"), "subject", "first"), ...(serial ? { id: 1 } : {}) };
        const second = { ...values(reservationId("subject"), "subject", "second"), ...(serial ? { id: 2 } : {}) };
        expect(context.raw()).toStrictEqual([
          reservationStorage(backend, first),
          ...(!duplicate ? [reservationStorage(backend, second)] : []),
        ]);
      } finally { context.close(); }
    });
  }

  for (const existing of [false, true]) {
    test(`${backend} Verification reservation input failure ${existing ? "finds the original primary key" : "preserves the original error"}`, async () => {
      const events: unknown[] = [];
      const failure = new TypeError("verification-reservation-input-rejected");
      let enabled = false;
      const context = await setup(backend, {
        ...reservationDates,
        value: { type: "string", transform: {
          input(value) {
            if (enabled) { events.push(["input", value]); throw failure; }
            return value;
          },
          output(value) { if (enabled) events.push(["output", value]); return value; },
        } },
      });
      try {
        const retained = values(reservationId("subject"), "different-identifier", "existing");
        if (existing) expect(await context.adapter.create({ model: "verification", data: retained, forceAllowId: true })).toStrictEqual(retained);
        enabled = true;
        let caught: unknown;
        let result: unknown;
        try {
          result = await context.internalAdapter.reserveVerificationValue({ identifier: "subject", value: "before", expiresAt: date(100) });
        } catch (error) { caught = error; }
        expect(result).toBe(existing ? false : undefined);
        expect(caught).toBe(existing ? undefined : failure);
        expect(events).toStrictEqual([["input", "before"], ...(existing ? [["output", "existing"]] : [])]);
        expect(context.raw()).toStrictEqual(existing ? [reservationStorage(backend, retained)] : []);
      } finally { context.close(); }
    });
  }

  test(`${backend} Verification reservation constructs its timestamps and ignores caller additional fields`, async () => {
    const events: unknown[] = [];
    const observedDates: Date[] = [];
    const captureDate = (phase: string, value: unknown) => {
      expect(value).toBeInstanceOf(Date);
      observedDates.push(value as Date);
      events.push([phase, value]);
      return date(0);
    };
    const context = await setup(backend, {
      value: { type: "string", transform: {
        input(value) { events.push(["value-input", value]); return "before"; },
        output(value) { events.push(["value-output", value]); return value; },
      } },
      createdAt: { type: "date", transform: { input(value) { return captureDate("created-input", value); } } },
      updatedAt: { type: "date", transform: { input(value) { return captureDate("updated-input", value); } } },
      probe: { type: "string", fieldName: "value", defaultValue: "default-probe", transform: {
        input(value) { events.push(["probe-input", value]); return value; },
        output(value) { events.push(["probe-output", value]); return value; },
      } },
    });
    try {
      const input = {
        identifier: "subject", value: "before", expiresAt: date(100),
        createdAt: date(-100), updatedAt: date(-100), probe: "caller-probe",
      };
      const started = Date.now();
      expect(await context.internalAdapter.reserveVerificationValue(input)).toBe(true);
      const finished = Date.now();
      expect(observedDates).toHaveLength(2);
      expect(observedDates[0]).not.toBe(observedDates[1]);
      expect(observedDates[0]).not.toBe(input.createdAt);
      expect(observedDates[1]).not.toBe(input.updatedAt);
      for (const value of observedDates) {
        expect(value.getTime()).toBeGreaterThanOrEqual(started);
        expect(value.getTime()).toBeLessThanOrEqual(finished);
      }
      expect(events).toStrictEqual([
        ["value-input", "before"], ["created-input", observedDates[0]], ["updated-input", observedDates[1]],
        ["probe-input", "default-probe"], ["value-output", "default-probe"], ["probe-output", "default-probe"],
      ]);
      expect(context.raw()).toStrictEqual([reservationStorage(backend, values(reservationId("subject"), "subject", "default-probe"))]);
    } finally { context.close(); }
  });

  for (const idFirst of [false, true]) {
    test(`${backend} Verification reservation preserves the UUID ID slot ${idFirst ? "before" : "after"} reentrant output`, async () => {
      const events: unknown[] = [];
      let context: Awaited<ReturnType<typeof setup>>;
      const id = { type: "string" as const, fieldName: "ignored", transform: {
        input() { throw new Error("configured-reservation-id-input-called"); },
        output() { throw new Error("configured-reservation-id-output-called"); },
      } };
      const probe = { type: "string" as const, fieldName: "value", defaultValue: "probe", transform: {
        async input(value: unknown) {
          events.push(["probe-input", value]);
          const nested = await context.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: "retained" }] });
          events.push(["nested-read", nested]);
          return undefined;
        },
        output(value: unknown) { events.push(["probe-output", value]); return value; },
      } };
      context = await setup(backend, {
        ...reservationDates,
        ...(idFirst ? { id, probe } : { probe, id }),
      }, "uuid");
      try {
        const writer = await betterAuth({ ...context.options, verification: undefined, advanced: undefined }).$context;
        const retained = values("retained", "retained", "retained-proof");
        expect(await writer.adapter.create({ model: "verification", data: retained, forceAllowId: true })).toStrictEqual(retained);
        let caught: unknown;
        let result: unknown;
        try {
          result = await context.internalAdapter.reserveVerificationValue({ identifier: "subject", value: "before", expiresAt: date(100) });
        } catch (error) { caught = error; }
        const succeeds = backend === "memory" || !idFirst;
        expect(result).toBe(succeeds ? true : undefined);
        if (succeeds) expect(caught).toBeUndefined();
        else {
          expect(caught).toBeInstanceOf(Error);
          const error = caught as Error & { code?: string; errno?: number };
          expect({ name: error.name, message: error.message, code: error.code, errno: error.errno }).toStrictEqual({
            name: "SQLiteError", message: "NOT NULL constraint failed: verification.id", code: "SQLITE_CONSTRAINT_NOTNULL", errno: 1299,
          });
        }
        expect(events).toStrictEqual([
          ["probe-input", "probe"], ["probe-output", "retained-proof"], ["nested-read", { ...retained, probe: "retained-proof" }],
          ...(succeeds ? [["probe-output", "before"]] : []),
        ]);
        const created = values(reservationId("subject"), "subject", "before");
        const { id: _, ...withoutId } = created;
        const rows: Fields[] = [reservationStorage(backend, retained), ...(succeeds ? [reservationStorage(backend, idFirst ? withoutId : created)] : [])];
        if (backend === "sqlite") rows.sort((left, right) => String(left.id) < String(right.id) ? -1 : 1);
        expect(context.raw()).toStrictEqual(rows);
      } finally { context.close(); }
    });
  }
}
