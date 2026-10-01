import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("rate-limit environment defaults and explicit switches use a fresh upstream process", () => {
  const script = fileURLToPath(new URL("./rate-limit-environment.mjs", import.meta.url));
  for (const environment of ["development", "production"]) {
    for (const configured of ["omitted", "false", "true"]) {
      const result = Bun.spawnSync({
        cmd: [process.execPath, script, configured],
        env: { ...process.env, NODE_ENV: environment },
        stdout: "pipe", stderr: "pipe",
      });
      expect(result.exitCode, result.stderr.toString()).toBe(0);
      expect(JSON.parse(result.stdout.toString())).toEqual({
        enabled: configured === "omitted" ? environment === "production" : configured === "true",
        window: 10, max: 100,
      });
    }
  }
});
