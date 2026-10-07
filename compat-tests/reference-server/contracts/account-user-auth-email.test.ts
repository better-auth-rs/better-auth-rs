import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("Array-owner OAuth email verification preserves rejection, logging, and stored rows", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/account-user-auth-email-1.7.6.json", import.meta.url), "utf8"));
  expect(fixture.version).toBe("1.7.6");
  expect(fixture.cases).toHaveLength(8);
  expect(fixture.scenarios.map((scenario: { name: string }) => scenario.name)).toStrictEqual([
    "social-owner-many-email-sender", "social-owner-many-email-no-sender",
  ]);
  const capture = fileURLToPath(new URL("account-user-auth-email-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toStrictEqual(fixture);
}, 60_000);
