import { expect, test } from "bun:test";
import type { BetterAuthOptions } from "better-auth";
import {
  created, date, generator, idSentinel, retained, row, setup, withoutId,
  type Backend, type Fields,
} from "./account-id-input-support";

type Slot = "implicit" | "before-alias" | "after-alias";
type Mode = "generated" | "supplied" | "generator-error" | "field-error";
type Field = NonNullable<NonNullable<BetterAuthOptions["account"]>["additionalFields"]>[string];

async function slotCase(backend: Backend, slot: Slot, mode: Mode) {
  const fixture = await setup(backend);
  try {
    const events: unknown[] = [];
    const generatorFailure = new TypeError("account-id-generator-rejected");
    const fieldFailure = new TypeError("account-field-input-rejected");
    const aliasId: Field = {
      type: "string" as const, fieldName: "id", transform: {
        input(value) {
          events.push(["alias-input", value]);
          if (mode === "field-error") throw fieldFailure;
          return "alias";
        },
        output(value) { events.push(["alias-output", value]); return value; },
      },
    };
    const additionalFields = slot === "before-alias" ? { id: idSentinel(), aliasId }
      : slot === "after-alias" ? { aliasId, id: idSentinel() } : { aliasId };
    const reader = await fixture.reader({
      account: { additionalFields },
      advanced: { database: { generateId: generator(events, mode === "generator-error" ? generatorFailure : undefined) } },
    }, events);
    const data = { ...(mode === "supplied" ? row("supplied") : withoutId(row(undefined))), aliasId: "alias-source" };
    const operation = () => reader.withHooks.createWithHooks(data, "account");
    const trace: unknown[] = [];
    for (const isId of slot === "before-alias" ? [true, false] : [false, true]) {
      if (isId && mode !== "supplied") {
        trace.push(["generate", "account"]);
        if (mode === "generator-error") break;
      } else if (!isId) {
        trace.push(["alias-input", "alias-source"]);
        if (mode === "field-error") break;
      }
    }
    const stored = [fixture.stored(retained())];
    if (mode === "generator-error" || mode === "field-error") {
      let caught: unknown;
      try { await operation(); } catch (error) { caught = error; }
      expect(caught).toBe(mode === "generator-error" ? generatorFailure : fieldFailure);
    } else {
      const id = slot === "before-alias" ? "alias" : mode === "supplied" ? "supplied" : "generated";
      const projected = { ...row(id), aliasId: id };
      await created(operation, projected);
      trace.push(["alias-output", id], ["after-create", projected]);
      stored.push(fixture.stored(row(id)));
    }
    expect(events).toStrictEqual(trace);
    expect(fixture.storage()).toStrictEqual(stored);
  } finally { fixture.close(); }
}

async function nativeCase(backend: Backend, id: 7 | false | 0) {
  const fixture = await setup(backend);
  try {
    const events: unknown[] = [];
    const reader = await fixture.reader({ advanced: { database: { generateId: generator(events) } } }, events);
    const succeeds = id === 7 || backend === "memory";
    const projected = row(id === 7 ? "7" : undefined);
    await created(() => reader.withHooks.createWithHooks(row(id), "account"), succeeds ? projected : null);
    expect(events).toStrictEqual(succeeds ? [["after-create", projected]] : []);
    expect(fixture.storage()).toStrictEqual([
      fixture.stored(retained()),
      ...(succeeds ? [fixture.stored(id === 7 ? row(id) : withoutId(row(undefined)))] : []),
    ]);
  } finally { fixture.close(); }
}

type UpdateId = "false" | "zero" | "empty" | "serial";
async function updateCase(backend: Backend, id: UpdateId, many: boolean) {
  const fixture = await setup(backend);
  try {
    const serial = id === "serial";
    await fixture.seed(row(serial ? 1 : "target"));
    const events: unknown[] = [];
    const idField = idSentinel();
    const reader = await fixture.reader({
      ...(serial ? { advanced: { database: { generateId: "serial" } } } : {}),
      account: { additionalFields: {
        accessToken: { type: "string", transform: {
          input(value) { events.push(["token-input", value]); return value; },
          output(value) { events.push(["token-output", value]); return value; },
        } },
        id: { type: idField.type, transform: idField.transform },
      } },
    }, events);
    const value = { false: false, zero: 0, empty: "", serial: "00101" }[id];
    const patch = { id: value, accessToken: "after", updatedAt: date(1) };
    const where = [{ field: "id", value: serial ? "001" : "target" }];
    const projected = { ...row(serial ? "101" : "target"), accessToken: "after", updatedAt: date(1) };
    const trace: unknown[] = [["token-input", "after"]];
    if (many) {
      expect(await reader.withHooks.updateManyWithHooks(patch, where, "account")).toBe(1);
      trace.push(["after-update", 1]);
    } else {
      expect(await reader.withHooks.updateWithHooks(patch, where, "account")).toStrictEqual(projected);
      trace.push(["token-output", "after"], ["after-update", projected]);
    }
    expect(events).toStrictEqual(trace);
    expect(fixture.storage()).toStrictEqual([
      fixture.stored(retained()), fixture.stored({ ...projected, id: serial ? 101 : "target" }),
    ]);
  } finally { fixture.close(); }
}

async function reentrantCase(backend: Backend, found: boolean, idFirst: boolean) {
  const fixture = await setup(backend);
  try {
    const existing = row("existing", "existing", "existing");
    if (found) await fixture.seed(existing);
    const events: unknown[] = [];
    let reader: Awaited<ReturnType<typeof fixture.reader>>;
    const probe: Field = {
      type: "string" as const, fieldName: "scope", transform: {
        async input(value) {
          events.push(["probe-input", value]);
          const nested = await reader.context.internalAdapter.findAccountByKey({
            providerId: "provider", accountId: found ? "existing" : "missing",
          });
          events.push(["nested-read", nested]);
          return value;
        },
      },
    };
    const options: BetterAuthOptions = {
      advanced: { database: { generateId: found ? generator(events) : "uuid" } },
      account: { additionalFields: idFirst ? { id: idSentinel(), probe } : { probe, id: idSentinel() } },
    };
    reader = await fixture.reader(options, events);
    const data = { ...(found ? withoutId(row(undefined)) : row("not-a-uuid")), probe: "outer" };
    const hasId = found ? idFirst : !idFirst;
    const id = hasId ? found ? "generated" : "not-a-uuid" : undefined;
    const succeeds = hasId || backend === "memory";
    const raw: Fields = { ...(hasId ? row(id) : withoutId(row(undefined))), scope: "outer" };
    const projected = { ...raw, id, probe: "outer" };
    await created(() => reader.withHooks.createWithHooks(data, "account"), succeeds ? projected : null);
    const trace: unknown[] = [];
    if (found && idFirst) trace.push(["generate", "account"]);
    trace.push(["probe-input", "outer"], ["nested-read", found ? { ...existing, probe: "read" } : null]);
    if (succeeds) trace.push(["after-create", projected]);
    expect(events).toStrictEqual(trace);
    expect(fixture.storage()).toStrictEqual([
      fixture.stored(retained()), ...(found ? [fixture.stored(existing)] : []),
      ...(succeeds ? [fixture.stored(raw)] : []),
    ]);
  } finally { fixture.close(); }
}

async function batchOutputResetCase(backend: Backend) {
  const fixture = await setup(backend);
  try {
    const second = row("second", "second-subject", "second");
    await fixture.seed(second);
    const events: unknown[] = [];
    let reader: Awaited<ReturnType<typeof fixture.reader>>;
    const probe: Field = { type: "string", fieldName: "accessToken", transform: {
      async input(value) {
        events.push(["probe-input", value]);
        if (value === "outer") events.push(["nested-list", await reader.context.adapter.findMany({
          model: "account", where: [{ field: "userId", value: "owner" }],
        })]);
        return value;
      },
      async output(value) {
        events.push(["probe-output", value]);
        if (value === "retained") {
          // Direct adapter lookup installs the ID policy before the callback's first await.
          const pending = reader.context.adapter.findMany({
            model: "account", where: [{ field: "userId", value: "missing" }],
          });
          events.push(["missing-started", value]);
          events.push(["nested-missing", await pending]);
        }
        return value;
      },
    } };
    reader = await fixture.reader({
      account: { additionalFields: { probe, id: idSentinel() } },
      advanced: { database: { generateId: generator(events) } },
    }, events);
    const raw = { ...withoutId(row(undefined)), accessToken: "outer" };
    const projected = { ...raw, id: undefined, probe: "outer" };
    await created(() => reader.withHooks.createWithHooks({
      ...withoutId(row(undefined)), probe: "outer",
    }, "account"), backend === "memory" ? projected : null);
    expect(events).toStrictEqual([
      ["probe-input", "outer"],
      ["probe-output", "retained"],
      ["missing-started", "retained"],
      ["probe-output", "second"],
      ["nested-missing", []],
      ["nested-list", [{ ...retained(), probe: "retained" }, { ...second, probe: "second" }]],
      ...(backend === "memory" ? [["probe-output", "outer"], ["after-create", projected]] : []),
    ]);
    expect(fixture.storage()).toStrictEqual([
      fixture.stored(retained()), fixture.stored(second),
      ...(backend === "memory" ? [fixture.stored(raw)] : []),
    ]);
  } finally { fixture.close(); }
}

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} Account batch output resets ID policy for each row`, () => batchOutputResetCase(backend));
  for (const slot of ["implicit", "before-alias", "after-alias"] as const) {
    for (const mode of ["generated", "supplied", "generator-error", "field-error"] as const) {
      test(`${backend} Account ID ${slot} ${mode} preserves input order and storage`, () => slotCase(backend, slot, mode));
    }
  }
  for (const id of [7, false, 0] as const) {
    test(`${backend} Account native supplied ID ${id} preserves omission and affinity`, () => nativeCase(backend, id));
  }
  for (const id of ["false", "zero", "empty", "serial"] as const) {
    for (const many of [false, true]) {
      test(`${backend} Account ${many ? "updateMany" : "update"} ID ${id} converts the native input`, () => updateCase(backend, id, many));
    }
  }
  for (const found of [false, true]) {
    for (const idFirst of [false, true]) {
      test(`${backend} Account ID ${idFirst ? "before" : "after"} ${found ? "found" : "missing"} lookup reads current policy`, () => reentrantCase(backend, found, idFirst));
    }
  }
}
