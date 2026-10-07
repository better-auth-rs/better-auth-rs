import { expect, test } from "bun:test";
import { captureNativeJsonDriver } from "./native-json-driver-capture.mjs";

test("SQLite native JSON preserves every result, callback, diagnostic and stored value", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/native-json-driver-sqlite-1.7.6.json", import.meta.url)).json();
  const observed = await captureNativeJsonDriver("sqlite");
  expect(observed.version).toBe("1.7.6");
  expect(observed.cases).toHaveLength(10);
  expect(observed).toStrictEqual(fixture);
});
