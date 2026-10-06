import { expect, test } from "bun:test";
import { captureDeviceOwnership } from "./device-ownership-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/device-ownership-1.7.6.json", import.meta.url)).json();

test("Device ownership preserves complete callback, consumption and transaction observations in pinned Memory and SQLite", async () => {
  const captured = await captureDeviceOwnership();
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) {
    expect(backend.cases.map(({ name, mode }: { name: string; mode: string }) => [name, mode])).toStrictEqual([
      ["tenant-match-after-prepare", "direct"],
      ["tenant-match-after-prepare", "transaction"],
      ["tenant-mismatch-after-prepare", "direct"],
      ["tenant-mismatch-after-prepare", "transaction"],
      ["or-tenant-mismatch", "direct"],
      ["or-tenant-mismatch", "transaction"],
      ["or-selects-earlier-owner", "direct"],
      ["scope-match-after-prepare", "direct"],
      ["scope-match-after-prepare", "transaction"],
      ["scope-mismatch-after-prepare", "direct"],
      ["scope-mismatch-after-prepare", "transaction"],
    ]);
  }
  expect(captured).toStrictEqual(fixture);
});
