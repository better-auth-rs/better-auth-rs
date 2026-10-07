import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("Member User joins preserve the complete pinned relation, projection, and failure contract", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/organization-member-join-reference-1.7.6.json", import.meta.url), "utf8"));
  const capture = fileURLToPath(new URL("organization-member-join-reference-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toStrictEqual(fixture);
}, 60_000);
