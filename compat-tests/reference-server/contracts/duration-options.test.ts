import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("SQLite reset lifetimes and initialization duration options match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./duration-options.mjs", import.meta.url))],
    env: { ...process.env, NODE_ENV: "production", TEST: "", BETTER_AUTH_TELEMETRY_ENDPOINT: "https://duration-options.test/capture", DURATION_OPTIONS_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
