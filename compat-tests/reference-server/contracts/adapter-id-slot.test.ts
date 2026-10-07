import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
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
