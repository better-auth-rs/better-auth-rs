import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureAdapterIdSlots } from "./adapter-id-slot-capture.mjs";

test("adapter ID policies retain explicit slots and reentrant schema changes", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/adapter-id-slot-1.7.6.json", import.meta.url), "utf8"));
  const actual = await captureAdapterIdSlots();
  expect(actual).toStrictEqual(fixture);
  expect(actual.version).toBe("1.7.6");
  expect(actual.cases).toHaveLength(16);
}, 30_000);
