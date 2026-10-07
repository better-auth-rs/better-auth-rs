import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("join reference history preserves the complete pinned adapter and transaction observations", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/schema-join-reference-history-1.7.6.json", import.meta.url), "utf8"));
  const capture = fileURLToPath(new URL("schema-join-reference-history-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toStrictEqual({ status: 0, stderr: "" });
  const actual = JSON.parse(stdout);
  expect(actual).toStrictEqual(fixture);
  expect(actual.version).toBe("1.7.6");
  expect(actual.cases).toHaveLength(48);
  expect(actual.transactions).toHaveLength(32);
  expect([...new Set(actual.cases.map((item: { name: string }) => item.name))]).toStrictEqual([
    "repeated-owner", "reversed-order", "ordinary-missing-read", "empty-where-null-read",
    "unknown-where-field", "failed-join-warmup", "primary-id-alias",
    "input-callback-failure", "output-without-where", "output-callback-failure",
  ]);
}, 30_000);
