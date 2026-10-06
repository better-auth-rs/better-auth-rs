import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import fixture from "../../../tests/fixtures/schema-join-reference-unknown-1.7.6.json";

test("unknown reference models preserve the complete pinned join boundary", async () => {
  const capture = fileURLToPath(new URL("schema-join-reference-unknown-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toEqual(fixture);
}, 30_000);
