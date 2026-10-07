import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("Email verification retains fractional JWT claims and exact consumption boundaries", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/email-verification-duration-1.7.6.json", import.meta.url)).json();
  const capture = fileURLToPath(new URL("email-verification-duration-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toStrictEqual(fixture);
}, 60_000);
