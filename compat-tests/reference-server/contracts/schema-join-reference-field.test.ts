import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

test("selected reference fields preserve the complete pinned join boundary", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/schema-join-reference-field-1.7.6.json", import.meta.url), "utf8"));
  const capture = fileURLToPath(new URL("schema-join-reference-field-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toEqual(fixture);
}, 30_000);
