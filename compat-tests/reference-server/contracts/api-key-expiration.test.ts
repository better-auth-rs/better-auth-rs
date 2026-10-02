import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("API Key expiration configuration matches the ordinary SQLite Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./api-key-expiration.mjs", import.meta.url))],
    env: { ...process.env, API_KEY_EXPIRATION_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
