import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("cookie lifetime resolution and browser output match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./cookie-lifetime.mjs", import.meta.url))],
    env: { ...process.env, COOKIE_LIFETIME_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
