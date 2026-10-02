import { ok } from "node:assert/strict";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

const base = {
  baseURL: "http://memory-record-fields.test",
  secret: "ordinary-memory-record-fields-secret-at-least-32-characters",
  logger: { disabled: true },
  telemetry: { enabled: false },
};
const instant = () => new Date("2030-01-01T00:00:00Z");
const expiresAt = () => new Date("2100-01-01T00:00:00Z");
type Scenario = "display" | "serial-reference" | "array-reference";

function policies(scenario: Scenario, events: unknown[]) {
  const fields = scenario === "display" ? {
    settings: { type: "json" as const, fieldName: "stored_settings" },
    labels: { type: "string[]" as const, fieldName: "stored_labels" },
    displayOrder: { type: "number[]" as const, fieldName: "stored_order" },
  } : {
    displayRefs: {
      type: scenario === "serial-reference" ? "json" as const : "string[]" as const,
      fieldName: "stored_display_refs",
      references: { model: "user", field: "id" },
    },
  };
  return Object.fromEntries(Object.entries(fields).map(([name, field]) => [name, {
    ...field,
    required: false,
    transform: {
      input(value: unknown) { events.push(["input", name, value]); return value; },
      output(value: unknown) { events.push(["output", name, value]); return value; },
    },
  }]));
}

function displayInput(updated: boolean) {
  return updated
    ? { settings: { theme: "dark", compact: false }, labels: ["updated"], displayOrder: [3] }
    : { settings: { theme: "light", compact: true }, labels: ["first", "second"], displayOrder: [1, 2] };
}

export async function captureMemoryRecordRepresentation() {
  const cases = [];
  for (const model of ["account", "verification"] as const) {
    for (const scenario of ["display", "serial-reference", "array-reference"] as const) {
      const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [] };
      const events: unknown[] = [];
      const fields = policies(scenario, events);
      const names = Object.keys(fields);
      const select = (row: Record<string, unknown>) => Object.fromEntries(names.map(name => [name, row[name]]));
      let sequence = 0;
      const generateId = scenario === "serial-reference"
        ? "serial" as const
        : scenario === "array-reference"
          ? ({ model }: { model: string }) => `display-${model}-${++sequence}`
          : undefined;
      const options = {
        ...base,
        database: memoryAdapter(memory),
        advanced: { database: { generateId } },
        [model]: { additionalFields: fields },
      };
      const { adapter } = await betterAuth(options).$context;
      const users = [];
      for (const label of ["first", "second"]) {
        users.push(await adapter.create<any>({ model: "user", data: {
          name: `${label} display seed`, email: `${label}@memory-record-fields.test`, emailVerified: false,
          createdAt: instant(), updatedAt: instant(),
        } }));
      }
      const input = scenario === "display" ? displayInput(false) : { displayRefs: users.map(user => user.id) };
      const native = model === "account"
        ? { userId: users[0].id, providerId: "ordinary", accountId: "display-row", createdAt: instant(), updatedAt: instant() }
        : { identifier: "ordinary-display", value: "display-value", expiresAt: expiresAt(), createdAt: instant(), updatedAt: instant() };
      events.push(["operation", "create"]);
      const created = await adapter.create<Record<string, unknown>>({ model, data: { ...native, ...input } });
      const where = model === "account"
        ? [{ field: "providerId", value: "ordinary" }, { field: "accountId", value: "display-row" }]
        : [{ field: "identifier", value: "ordinary-display" }];
      events.push(["operation", "read"]);
      const read = await adapter.findOne<Record<string, unknown>>({ model, where });
      ok(read, "the ordinary display record exists");
      let result: unknown = { created: select(created), read: select(read) };
      if (scenario === "display") {
        events.push(["operation", "update"]);
        const updated = await adapter.update<Record<string, unknown>>({
          model,
          where: model === "account" ? [{ field: "id", value: created.id as string }] : where,
          update: displayInput(true),
        });
        ok(updated, "the display update returns a record");
        events.push(["operation", "reread"]);
        const reread = await adapter.findOne<Record<string, unknown>>({ model, where });
        ok(reread, "the updated display record exists");
        result = { created: select(created), read: select(read), updated: select(updated), reread: select(reread) };
      }
      const row = memory[model][0];
      ok(row, "the raw display record exists");
      const stored = Object.fromEntries(names.map(name => [name, row[fields[name].fieldName]]));
      cases.push({ model, scenario, events, result, stored });
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureMemoryRecordRepresentation(), null, 2));
