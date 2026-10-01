import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("real initialization cache options and session lifetime match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./telemetry-cache-init.mjs", import.meta.url))],
    env: { ...process.env, NODE_ENV: "production", TEST: "", BETTER_AUTH_TELEMETRY_ENDPOINT: "https://telemetry-cache-init.test/capture", TELEMETRY_CACHE_INIT_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
