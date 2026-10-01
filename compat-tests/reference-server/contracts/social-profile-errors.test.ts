import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("ordinary Social profile results preserve null versus original errors", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./social-profile-errors.mjs", import.meta.url))],
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  expect(result.stdout.toString()).toContain("88 ordinary Social profile error contracts passed");
  expect(result.stdout.toString()).toContain("24 typed UserInfo API error contracts passed");
});
