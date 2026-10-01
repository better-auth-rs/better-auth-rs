import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("real initialization plugin IDs match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./telemetry-plugin-ids.mjs", import.meta.url))],
    env: { ...process.env, NODE_ENV: "production", TEST: "", BETTER_AUTH_TELEMETRY_ENDPOINT: "https://telemetry-plugin-ids.test/capture", TELEMETRY_PLUGIN_IDS_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
