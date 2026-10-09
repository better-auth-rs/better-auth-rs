import { expect, test } from "bun:test";
import {
  created, entries, generator, idSentinel, models, probeColumn, referencesAsStrings, row, setup, withoutId,
  type Backend, type Entry, type Fields, type Model, type Policies,
} from "./organization-id-input-support";

type Native = "absent" | "undefined" | "null" | "seven" | "false" | "zero";

async function nativeCase(backend: Backend, entry: Entry, kind: Native) {
  const { model } = entry;
  const fixture = await setup(backend, model);
  try {
    const events: unknown[] = [];
    const reader = await fixture.reader({}, generator(events));
    const value = { absent: undefined, undefined, null: null, seven: 7, false: false, zero: 0 }[kind];
    const data = kind === "absent" ? withoutId(row(model, undefined)) : row(model, value);
    const generated = kind === "absent" || kind === "undefined" || kind === "null";
    const omitted = kind === "false" || kind === "zero";
    const id = generated ? "generated" : omitted ? undefined : "7";
    const succeeds = !omitted || backend === "memory";
    await created(model, () => reader.create({ model, forceAllowId: true, data }), succeeds ? row(model, id) : null);
    expect(events).toStrictEqual(generated ? [["generate", model]] : []);
    const raw = omitted ? withoutId(row(model, undefined)) : row(model, generated ? "generated" : 7);
    expect(fixture.storage()).toStrictEqual([
      fixture.stored(row(model, "retained", "retained")), ...(succeeds ? [fixture.stored(raw)] : []),
    ]);
  } finally { fixture.close(); }
}

type Slot = "implicit" | "before-alias" | "after-alias";
type Mode = "generated" | "supplied" | "generator-error" | "field-error";

async function slotCase(backend: Backend, entry: Entry, slot: Slot, mode: Mode) {
  const { model } = entry;
  const fixture = await setup(backend, model);
  try {
    const events: unknown[] = [];
    const generatorFailure = new TypeError("organization-id-generator-rejected");
    const fieldFailure = new TypeError("organization-field-input-rejected");
    const aliasId: Policies[string] = { type: "string", fieldName: "id", transform: {
      input(value) {
        events.push(["alias-input", value]);
        if (mode === "field-error") throw fieldFailure;
        return "alias";
      },
      output(value) { events.push(["alias-output", value]); return value; },
    } };
    const fields = slot === "before-alias" ? { id: idSentinel(), aliasId }
      : slot === "after-alias" ? { aliasId, id: idSentinel() } : { aliasId };
    const reader = await fixture.reader(fields, generator(events, mode === "generator-error" ? generatorFailure : undefined));
    const data = { ...(mode === "supplied" ? row(model, "supplied") : withoutId(row(model, undefined))), aliasId: "alias-source" };
    const trace: unknown[] = [];
    for (const field of slot === "before-alias" ? ["id", "alias"] : ["alias", "id"]) {
      if (field === "id" && mode !== "supplied") {
        trace.push(["generate", model]);
        if (mode === "generator-error") break;
      } else if (field === "alias") {
        trace.push(["alias-input", "alias-source"]);
        if (mode === "field-error") break;
      }
    }
    const stored = [fixture.stored(row(model, "retained", "retained"))];
    if (mode === "generator-error" || mode === "field-error") {
      let caught: unknown;
      try { await reader.create({ model, forceAllowId: true, data }); } catch (error) { caught = error; }
      expect(caught).toBe(mode === "generator-error" ? generatorFailure : fieldFailure);
    } else {
      const id = slot === "before-alias" ? "alias" : mode === "supplied" ? "supplied" : "generated";
      expect(await reader.create({ model, forceAllowId: true, data })).toStrictEqual({ ...row(model, id), aliasId: id });
      trace.push(["alias-output", id]);
      stored.push(fixture.stored(row(model, id)));
    }
    expect(events).toStrictEqual(trace);
    expect(fixture.storage()).toStrictEqual(stored);
  } finally { fixture.close(); }
}

async function serialCase(backend: Backend, model: Model, idFirst: boolean) {
  const fixture = await setup(backend, model);
  try {
    const events: unknown[] = [];
    const aliasId: Policies[string] = { type: "string", fieldName: "id", transform: {
      input(value) { events.push(["alias-input", value]); return "alias"; },
      output(value) { events.push(["alias-output", value]); return value; },
    } };
    const fields = { ...referencesAsStrings(model), ...(idFirst ? { id: idSentinel(), aliasId } : { aliasId, id: idSentinel() }) };
    const reader = await fixture.reader(fields, "serial");
    const rawId = backend === "memory" ? 2 : idFirst ? "alias" : 101;
    const id = String(rawId);
    expect(await reader.create({ model, forceAllowId: true, data: { ...row(model, "00101"), aliasId: "alias-source" } }))
      .toStrictEqual({ ...row(model, id), aliasId: id });
    expect(events).toStrictEqual([["alias-input", "alias-source"], ["alias-output", backend === "memory" ? rawId : id]]);
    expect(fixture.storage()).toStrictEqual([
      fixture.stored(row(model, "retained", "retained")), fixture.stored(row(model, rawId)),
    ]);
  } finally { fixture.close(); }
}

type Reentrant = "found" | "missing" | "count" | "nested";

async function reentrantCase(backend: Backend, kind: Reentrant, idFirst: boolean) {
  const model = kind === "count" ? "organizationRole" : "organization";
  const fixture = await setup(backend, model);
  try {
    const events: unknown[] = [];
    const clearsInput = kind === "found" || kind === "nested";
    let reader: Awaited<ReturnType<typeof fixture.reader>>;
    const probe: Policies[string] = { type: "string", fieldName: probeColumn(model), transform: {
      async input(value) {
        events.push(["probe-input", value]);
        if (value !== "outer") return value;
        if (kind === "nested") {
          const nested = await reader.create({
            model, forceAllowId: true, data: { ...row(model, "nested", "nested"), probe: "inner" },
          });
          events.push(["nested-create", nested]);
        } else if (kind === "count") {
          events.push(["nested-count", await reader.count({
            model, where: [{ field: "organizationId", value: "parent" }],
          })]);
        } else {
          events.push(["nested-read", await reader.findOne({ model, where: [
            kind === "found" ? { field: "id", value: "retained" } : { field: "slug", value: "missing" },
          ] })]);
        }
        return value;
      },
    } };
    reader = await fixture.reader(
      idFirst ? { id: idSentinel(), probe } : { probe, id: idSentinel() },
      clearsInput ? generator(events) : "uuid",
    );
    const data = { ...(clearsInput ? withoutId(row(model, undefined)) : row(model, "not-a-uuid")), probe: "outer" };
    const hasId = clearsInput ? idFirst : !idFirst;
    const id = hasId ? clearsInput ? "generated" : "not-a-uuid" : undefined;
    const succeeds = hasId || backend === "memory";
    const raw: Fields = { ...(hasId ? row(model, id) : withoutId(row(model, undefined))), [probeColumn(model)]: "outer" };
    const projected = { ...raw, id, probe: "outer" };
    await created(model, () => reader.create({ model, forceAllowId: true, data }), succeeds ? projected : null);
    const trace: unknown[] = [];
    if (clearsInput && idFirst) trace.push(["generate", model]);
    trace.push(["probe-input", "outer"]);
    const stored = [fixture.stored(row(model, "retained", "retained"))];
    if (kind === "found") trace.push(["nested-read", { ...row(model, "retained", "retained"), probe: "retained" }]);
    else if (kind === "missing") trace.push(["nested-read", null]);
    else if (kind === "count") trace.push(["nested-count", 1]);
    else {
      const nested = { ...row(model, "nested", "nested"), [probeColumn(model)]: "inner" };
      trace.push(["probe-input", "inner"], ["nested-create", { ...nested, probe: "inner" }]);
      stored.push(fixture.stored(nested));
    }
    if (succeeds) stored.push(fixture.stored(raw));
    expect(events).toStrictEqual(trace);
    expect(fixture.storage()).toStrictEqual(stored);
  } finally { fixture.close(); }
}

async function batchOutputResetCase(backend: Backend) {
  const model = "organization";
  const fixture = await setup(backend, model);
  try {
    await fixture.seed(row(model, "second", "second"));
    const events: unknown[] = [];
    let reader: Awaited<ReturnType<typeof fixture.reader>>;
    const probe: Policies[string] = { type: "string", fieldName: "name", transform: {
      async input(value) {
        events.push(["probe-input", value]);
        if (value === "outer") events.push(["nested-list", await reader.findMany({
          model, where: [{ field: "id", operator: "in", value: ["retained", "second"] }],
        })]);
        return value;
      },
      async output(value) {
        events.push(["probe-output", value]);
        if (value === "retained") {
          // The query installs its ID input policy before the callback's first await.
          const pending = reader.findOne({ model, where: [{ field: "slug", value: "missing" }] });
          events.push(["missing-started", value]);
          events.push(["nested-missing", await pending]);
        }
        return value;
      },
    } };
    reader = await fixture.reader({ probe, id: idSentinel() }, generator(events));
    const raw = { ...withoutId(row(model, undefined)), name: "outer" };
    await created(model, () => reader.create({ model, forceAllowId: true, data: {
      ...withoutId(row(model, undefined)), probe: "outer",
    } }), backend === "memory" ? { ...raw, id: undefined, probe: "outer" } : null);
    expect(events).toStrictEqual([
      ["probe-input", "outer"],
      ["probe-output", "retained"],
      ["missing-started", "retained"],
      ["probe-output", "second"],
      ["nested-missing", null],
      ["nested-list", [
        { ...row(model, "retained", "retained"), probe: "retained" },
        { ...row(model, "second", "second"), probe: "second" },
      ]],
      ...(backend === "memory" ? [["probe-output", "outer"]] : []),
    ]);
    expect(fixture.storage()).toStrictEqual([
      fixture.stored(row(model, "retained", "retained")), fixture.stored(row(model, "second", "second")),
      ...(backend === "memory" ? [fixture.stored(raw)] : []),
    ]);
  } finally { fixture.close(); }
}

for (const idFirst of [true, false]) {
  test(`Memory Organization insert ID output failure ${idFirst ? "before" : "after"} probe preserves the write`, async () => {
    const fixture = await setup("memory", "organization");
    try {
      const events: unknown[] = [];
      const outputProbe: Policies[string] = { type: "string", fieldName: "logo", transform: {
        output(value) { events.push(["probe-output", value]); return value; },
      } };
      const reader = await fixture.reader(
        idFirst ? { id: idSentinel(), outputProbe } : { outputProbe, id: idSentinel() },
        generator(events),
      );
      const id = { toString: null, valueOf: null };
      const result = reader.create({ model: "organization", forceAllowId: true, data: {
        ...row("organization", id), outputProbe: "probe-source",
      } });
      await expect(result).rejects.toBeInstanceOf(TypeError);
      await expect(result).rejects.toMatchObject({ name: "TypeError", message: "No default value" });
      expect(events).toStrictEqual(idFirst ? [] : [["probe-output", "probe-source"]]);
      expect(fixture.storage()).toStrictEqual([
        row("organization", "retained", "retained"), { ...row("organization", id), logo: "probe-source" },
      ]);
    } finally { fixture.close(); }
  });
}

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} Organization batch output resets ID policy for each row`, () => batchOutputResetCase(backend));
  for (const entry of entries) {
    for (const kind of ["absent", "undefined", "null", "seven", "false", "zero"] as const) {
      test(`${backend} ${entry.model} ${entry.operation} native ID ${kind}`, () => nativeCase(backend, entry, kind));
    }
  }
  for (const slot of ["implicit", "before-alias", "after-alias"] as const) {
    for (const mode of ["generated", "supplied", "generator-error", "field-error"] as const) {
      test(`${backend} Organization create ID ${slot} ${mode}`, () => slotCase(backend, { model: "organization", operation: "create" }, slot, mode));
    }
  }
  for (const slot of ["before-alias", "after-alias"] as const) {
    test(`${backend} Member insert ID ${slot} generated`, () => slotCase(backend, { model: "member", operation: "insert" }, slot, "generated"));
  }
  for (const model of models) {
    for (const idFirst of [true, false]) {
      test(`${backend} ${model} Serial create ID ${idFirst ? "before" : "after"} alias`, () => serialCase(backend, model, idFirst));
    }
  }
  for (const kind of ["found", "missing", "count", "nested"] as const) {
    for (const idFirst of [true, false]) {
      test(`${backend} Organization ID ${idFirst ? "before" : "after"} same-runtime ${kind}`, () => reentrantCase(backend, kind, idFirst));
    }
  }
}
