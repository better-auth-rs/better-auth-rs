import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("LINE normal code-login contracts match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./line.mjs", import.meta.url))],
    env: { ...process.env, LINE_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
