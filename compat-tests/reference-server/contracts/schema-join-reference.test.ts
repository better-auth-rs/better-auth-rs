import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import fixture from "../../../tests/fixtures/schema-join-reference-1.7.6.json";
import aliasFixture from "../../../tests/fixtures/schema-join-reference-alias-1.7.6.json";

for (const [script, expected] of [
  ["schema-join-reference-capture.mjs", fixture],
  ["schema-join-reference-alias-capture.mjs", aliasFixture],
] as const) test(`${script} matches the pinned complete capture`, async () => {
  const capture = fileURLToPath(new URL(script, import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toEqual(expected);
}, 30_000);
