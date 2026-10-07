import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureUserSerialCreateOrder } from "./user-serial-create-order-capture.mjs";

test("Memory assigns serial User IDs after nested callbacks and retains failed-write ordering", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/user-serial-create-order-1.7.6.json", import.meta.url), "utf8"));
  const actual = JSON.parse(JSON.stringify(await captureUserSerialCreateOrder()));
  expect(actual).toStrictEqual(fixture);
  expect(actual.version).toBe("1.7.6");
  expect(actual.cases).toHaveLength(6);
}, 30_000);
