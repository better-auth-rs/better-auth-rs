import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} JWK schema matches the pinned default and mapped catalogs`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/jwk-${backend}-catalog-1.7.6.json`, import.meta.url), "utf8"));
    const directory = await mkdtemp(join(tmpdir(), "better-auth-jwk-catalog-"));
    try {
      const output = join(directory, "catalog.json");
      const sampler = fileURLToPath(new URL("../contracts/jwk-server-catalog-capture.mjs", import.meta.url));
      // Upstream mutates the shared JWT schema when applying custom mappings.
      const child = Bun.spawn([process.execPath, "--no-install", sampler, backend, output], {
        stdout: "inherit", stderr: "inherit",
      });
      expect(await child.exited).toBe(0);
      expect(JSON.parse(await readFile(output, "utf8"))).toEqual(fixture);
    } finally {
      await rm(directory, { recursive: true });
    }
  }, 30_000);
}
