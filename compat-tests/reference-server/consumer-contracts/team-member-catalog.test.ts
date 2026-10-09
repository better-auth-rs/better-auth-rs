import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

for (const backend of ["sqlite", "postgres", "mysql"]) {
  test(`${backend} TeamMember catalog and storage constraints match pinned upstream`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/team-member-catalog-${backend}-1.7.6.json`, import.meta.url), "utf8"));
    const directory = await mkdtemp(join(tmpdir(), "better-auth-team-member-catalog-"));
    try {
      const output = join(directory, "catalog.json");
      const sampler = fileURLToPath(new URL("../contracts/team-member-catalog-capture.mjs", import.meta.url));
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
