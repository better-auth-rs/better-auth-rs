import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("normal signed Google flows match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./google-profile.mjs", import.meta.url))],
    env: { ...process.env, GOOGLE_PROFILE_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
