import { expect, test } from "bun:test";

test("ordinary cookie cache lifetime matches the shared Rust fixture", () => {
  const result = Bun.spawnSync([process.execPath, new URL("./cookie-cache-lifetime.mjs", import.meta.url).pathname], {
    env: { ...process.env, COOKIE_CACHE_LIFETIME_OUTPUT: "" },
    stdout: "pipe", stderr: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
});
