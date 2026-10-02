import { expect, test } from "bun:test";
import { captureMemoryCoreJson } from "./memory-core-json";

const expected = await Bun.file(new URL("../../../tests/fixtures/memory-core-json-1.7.6.json", import.meta.url)).json();
const captured = await captureMemoryCoreJson();

test("User, Session and Organization display fields preserve Memory JSON and array representations", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured.groups.map((group) => [group.name, group.operations.length])).toStrictEqual([
    ["user", 4], ["session", 4], ["organization-snapshot", 13], ["organization-joined-query", 2],
  ]);
  expect(captured).toStrictEqual(expected);
});
