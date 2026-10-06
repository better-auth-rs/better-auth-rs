import { expect, test } from "bun:test";
import { captureTwoFactorFields } from "./two-factor-fields-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/two-factor-fields-1.7.6.json", import.meta.url)).json();

test("TwoFactor additional fields preserve complete JSON callback traces, records and mutation phases in pinned Memory and SQLite", async () => {
  const captured = await captureTwoFactorFields();
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) {
    expect(backend.operations).toHaveLength(12);
    expect(backend.failures).toHaveLength(6);
  }
  expect(captured).toStrictEqual(fixture);
});
