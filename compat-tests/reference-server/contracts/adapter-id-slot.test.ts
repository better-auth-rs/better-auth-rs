import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { captureAdapterIdSlots } from "./adapter-id-slot-capture.mjs";

test("adapter ID policies retain explicit slots and reentrant schema changes", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/adapter-id-slot-1.7.6.json", import.meta.url), "utf8"));
  const actual = await captureAdapterIdSlots();
  expect(actual).toStrictEqual(fixture);
  expect(actual.version).toBe("1.7.6");
  expect(actual.cases).toHaveLength(25);
  expect(actual.cases.at(-1)).toMatchObject({
    model: "session", slot: "after-alias", operation: "update-undefined-id-alias", idGeneration: "serial",
    seedEvents: [["input", "aliasId", "seed"], ["output", "aliasId", 1]],
    before: { session: [{ id: 1 }] },
    events: [["input", "aliasId", "clear"], ["output", "aliasId", { type: "number", value: "NaN" }]],
    result: { id: "NaN", aliasId: "NaN" },
    error: null,
    after: { session: [{ id: { type: "number", value: "NaN" } }] },
  });
}, 30_000);

test("literal Undefined defaults preserve omission and required null before Serial reference binding", async () => {
  for (const factory of [false, true]) {
    for (const nullInput of [false, true]) {
      const memory = { user: [], account: [], session: [], verification: [] };
      const events: unknown[] = [];
      const context = await betterAuth({
        database: memoryAdapter(memory), baseURL: "http://adapter-id-slot.test",
        secret: "adapter-id-slot-contract-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        advanced: { database: { generateId: "serial" } },
        session: { additionalFields: {
          reference: {
            type: "string", required: true, fieldName: "storedReference",
            references: { model: "session", field: "id" },
            defaultValue: factory ? () => {
              events.push(["default"]);
              return undefined;
            } : undefined,
            transform: { output(value) {
              events.push(["output", value]);
              return value;
            } },
          },
        } },
      }).$context;
      const values = {
        token: `default-${factory}-${nullInput}`, userId: "7",
        expiresAt: new Date("2100-01-02T03:04:05.000Z"),
        createdAt: new Date("2030-01-02T03:04:05.000Z"),
        updatedAt: new Date("2030-01-02T03:04:05.000Z"),
        ipAddress: "", userAgent: "",
      };
      const result = await context.adapter.create({
        model: "session", data: { ...values, ...(nullInput ? { reference: null } : {}) },
      });
      const bound = factory ? NaN : nullInput ? null : undefined;
      expect(events).toStrictEqual([
        ...(factory ? [["default"]] : []), ["output", bound],
      ]);
      expect(memory).toStrictEqual({
        user: [], account: [], verification: [],
        session: [{
          ...values, userId: 7, id: 1,
          ...(factory || nullInput ? { storedReference: bound } : {}),
        }],
      });
      expect(result).toStrictEqual({ ...values, id: "1", reference: factory ? "NaN" : bound });
    }
  }
}, 30_000);
