import { expect, test } from "bun:test";
import { captureDeviceOwnershipSets } from "./device-ownership-set-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/device-ownership-set-1.7.6.json", import.meta.url)).json();

test("Device ownership set conditions preserve complete callback, decoy, consumption and transaction observations in pinned Memory and SQLite", async () => {
  const captured = await captureDeviceOwnershipSets();
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) {
    expect(backend.cases.map(({ name, mode }: { name: string; mode: string }) => [name, mode])).toStrictEqual([
      ["scope-in-match-after-prepare", "direct"],
      ["tenant-alias-in-mismatch-after-prepare", "direct"],
      ["tenant-not-in-match-after-prepare", "direct"],
      ["tenant-not-in-mismatch-after-prepare", "direct"],
      ["revision-in-numbers", "direct"],
      ["revision-in-numeric-strings", "direct"],
      ["revision-not-in-numeric-strings", "direct"],
      ["revision-in-mixed-strings", "direct"],
      ["tenant-in-empty", "direct"],
      ["tenant-not-in-empty", "direct"],
      ["tenant-null-not-in", "direct"],
      ["scope-in-match-after-prepare", "transaction"],
      ["tenant-alias-in-mismatch-after-prepare", "transaction"],
    ]);
  }
  expect(captured).toStrictEqual(fixture);
});
