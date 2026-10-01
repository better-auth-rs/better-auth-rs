import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("real initialization model declarations match the generated Rust consumer fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./telemetry-model-declarations.mjs", import.meta.url))],
    env: { ...process.env, NODE_ENV: "production", TEST: "", BETTER_AUTH_TELEMETRY_ENDPOINT: "https://telemetry-model-declarations.test/capture", TELEMETRY_MODEL_DECLARATIONS_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
