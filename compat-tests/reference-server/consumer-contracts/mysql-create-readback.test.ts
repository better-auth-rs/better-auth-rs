import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

test("mysql creation preserves readback, nullable hooks, secondary writes, and transaction boundaries", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/create-readback-mysql-1.7.6.json", import.meta.url), "utf8"));
  expect(fixture.version).toBe("1.7.6");
  expect(fixture.backend).toBe("mysql");
  expect(fixture.model).toBe("jwks");
  expect(fixture.cases.map((entry: { name: string }) => entry.name)).toStrictEqual([
    "explicit-id",
    "serial-id",
    "database-default-full-match",
    "mapped-unique-first-hit",
    "mapped-unique-first-miss-second-hit",
    "mapped-unique-null-skipped",
    "mapped-unique-empty-probed",
    "full-match-single-then-duplicate",
    "full-match-transaction-single-then-duplicate",
    "readback-error-direct",
    "readback-error-transaction",
  ]);
  expect(fixture.lifecycle.cases.map((entry: { name: string }) => entry.name)).toStrictEqual([
    "user-before-cancel-transaction",
    "user-written-null-direct",
    "user-written-null-transaction",
    "user-after-null-error-direct",
    "user-after-null-error-transaction",
    "user-written-null-rollback",
    "session-secondary-immediate",
    "session-secondary-deferred",
    "session-secondary-before-cancel",
    "session-secondary-deferred-after-error",
    "verification-secondary-immediate",
    "verification-secondary-before-cancel",
    "verification-secondary-after-error",
  ]);
  const directory = await mkdtemp(join(tmpdir(), "better-auth-mysql-create-readback-"));
  try {
    const output = join(directory, "observed.json");
    const sampler = fileURLToPath(new URL("../contracts/mysql-create-readback-capture.mjs", import.meta.url));
    // Upstream mutates the shared JWT schema when applying custom mappings.
    const child = Bun.spawn([process.execPath, "--no-install", sampler, "mysql", output], {
      stdout: "inherit", stderr: "inherit",
    });
    expect(await child.exited).toBe(0);
    expect(JSON.parse(await readFile(output, "utf8"))).toStrictEqual(fixture);
  } finally {
    await rm(directory, { recursive: true });
  }
}, 60_000);
