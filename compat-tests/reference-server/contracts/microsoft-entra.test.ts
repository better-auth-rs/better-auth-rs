import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("Microsoft Entra ID signed login contracts match the Rust fixture", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, fileURLToPath(new URL("./microsoft-entra.mjs", import.meta.url))],
    env: { ...process.env, MICROSOFT_ENTRA_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
