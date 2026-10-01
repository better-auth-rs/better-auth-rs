import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("real initialization storage context matches the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./telemetry-storage-init.mjs", import.meta.url))],
    env: { ...process.env, NODE_ENV: "production", TEST: "", BETTER_AUTH_TELEMETRY_ENDPOINT: "https://telemetry-storage-init.test/capture", TELEMETRY_STORAGE_INIT_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
