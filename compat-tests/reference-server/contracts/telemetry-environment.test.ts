import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("initialization environment metadata and suppression match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./telemetry-environment.mjs", import.meta.url))],
    env: { ...process.env, TELEMETRY_ENVIRONMENT_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
}, 30000);
