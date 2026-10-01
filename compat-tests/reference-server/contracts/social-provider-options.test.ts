import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("social provider configuration and normal profiles match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./social-provider-options.mjs", import.meta.url))],
    env: { ...process.env, NODE_ENV: "production", TEST: "", BETTER_AUTH_TELEMETRY_ENDPOINT: "https://social-provider-options.test/capture", SOCIAL_PROVIDER_OPTIONS_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
