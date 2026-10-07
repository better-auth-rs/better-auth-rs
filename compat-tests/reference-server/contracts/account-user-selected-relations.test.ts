import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("Account User reads execute the complete pinned selected-relation contract", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/account-user-selected-relations-1.7.6.json", import.meta.url), "utf8"));
  const capture = fileURLToPath(new URL("account-user-selected-relations-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toStrictEqual(fixture);
}, 60_000);
