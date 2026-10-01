import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("network option presence and resolution match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./network-options.mjs", import.meta.url))],
    env: { ...process.env, NODE_ENV: "production", NETWORK_REFERENCE_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
