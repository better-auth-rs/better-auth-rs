import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

for (const backend of ["sqlite", "postgres", "mysql"]) {
  test(`${backend} DeviceCode schema matches the pinned complete catalog`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/device-code-${backend}-catalog-1.7.6.json`, import.meta.url), "utf8"));
    const directory = await mkdtemp(join(tmpdir(), "better-auth-device-code-catalog-"));
    try {
      const output = join(directory, "catalog.json");
      const sampler = fileURLToPath(new URL("../contracts/device-code-catalog-capture.mjs", import.meta.url));
      // Upstream mutates shared DeviceCode field definitions when applying mappings.
      const child = Bun.spawn([process.execPath, "--no-install", sampler, backend, output], {
        stdout: "inherit", stderr: "inherit",
      });
      expect(await child.exited).toBe(0);
      expect(JSON.parse(await readFile(output, "utf8"))).toStrictEqual(fixture);
    } finally {
      await rm(directory, { recursive: true });
    }
  }, 30_000);
}
