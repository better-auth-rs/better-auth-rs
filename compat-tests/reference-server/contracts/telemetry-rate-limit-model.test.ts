import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("real initialization rate-limit model metadata matches the generated Rust consumer fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./telemetry-rate-limit-model.mjs", import.meta.url))],
    env: { ...process.env, NODE_ENV: "production", TEST: "", BETTER_AUTH_TELEMETRY_ENDPOINT: "https://telemetry-rate-limit-model.test/capture", TELEMETRY_RATE_LIMIT_MODEL_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
