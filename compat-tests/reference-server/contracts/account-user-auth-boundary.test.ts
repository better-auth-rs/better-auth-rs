import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("Account User authentication preserves the complete selected-relation consumption contract", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/account-user-auth-override-1.7.6.json", import.meta.url), "utf8"));
  const baseline = JSON.parse(readFileSync(new URL("../../../tests/fixtures/account-user-auth-boundary-1.7.6.json", import.meta.url), "utf8"));
  expect(fixture.scenarios.slice(0, 4)).toStrictEqual(baseline.scenarios);
  expect(fixture.cases.slice(0, 16)).toStrictEqual(baseline.cases);
  expect(fixture.scenarios.map((scenario: { name: string }) => scenario.name)).toStrictEqual([
    "social-alternate-owner", "social-owner-many", "social-accounts-one", "email-accounts-one",
    "social-owner-many-direct-override", "social-owner-many-callback-override",
  ]);
  expect(fixture.cases).toHaveLength(24);
  const capture = fileURLToPath(new URL("account-user-auth-boundary-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toStrictEqual(fixture);
}, 60_000);
