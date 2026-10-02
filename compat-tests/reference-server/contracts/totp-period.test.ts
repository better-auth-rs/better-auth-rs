import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import fixture from "../../../tests/fixtures/totp-period-1.7.6.json";

test("TOTP generation and URI preserve the configured period", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./totp-period.mjs", import.meta.url))],
    env: { ...process.env, TOTP_PERIOD_OUTPUT: "" },
    stdout: "pipe",
    stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  expect(JSON.parse(result.stdout.toString())).toEqual(fixture);
});
