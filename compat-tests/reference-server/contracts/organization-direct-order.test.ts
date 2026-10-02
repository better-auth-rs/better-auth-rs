import { expect, test } from "bun:test";
import { dirname, join } from "node:path";

test("Organization raw declarations and resolved plugin order match the pinned fixture", () => {
  const result = Bun.spawnSync([process.execPath, join(dirname(import.meta.path), "organization-direct-order.mjs")], {
    env: { ...process.env, ORGANIZATION_DIRECT_ORDER_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  expect(result.stdout.toString()).toContain("14 contracts");
});
