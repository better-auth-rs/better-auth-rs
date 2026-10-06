import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import fixture from "../../../tests/fixtures/schema-join-reference-conflict-1.7.6.json";

test("logical model names precede physical aliases in the complete pinned capture", async () => {
  const capture = fileURLToPath(new URL("schema-join-reference-conflict-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toEqual(fixture);
}, 30_000);
