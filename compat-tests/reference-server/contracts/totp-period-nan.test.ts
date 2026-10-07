import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import fixture from "../../../tests/fixtures/totp-period-nan-1.7.6.json";

test("TOTP NaN defaults preserve complete upstream operations and enrollment", async () => {
  const directory = mkdtempSync(join(tmpdir(), "better-auth-totp-nan-"));
  const output = join(directory, "capture.json");
  const capture = fileURLToPath(new URL("./totp-period-nan-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture, output], {
    stdout: "pipe", stderr: "pipe",
  });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  writeFileSync(join(directory, "stdout.log"), stdout);
  writeFileSync(join(directory, "stderr.log"), stderr);
  expect({ status, stderr }, `Capture evidence: ${directory}`).toEqual({ status: 0, stderr: "" });
  const actual = JSON.parse(readFileSync(output, "utf8"));
  expect(actual.cases.length).toBe(fixture.cases.length);
  for (const [index, entry] of actual.cases.entries()) {
    for (const operation of ["generation", "verification"] as const) {
      const properties = entry.helper[operation].error.properties;
      const expected = fixture.cases[index].helper[operation].error.properties;
      // Bun records the absolute dependency path. Validate the module before mapping the checkout location.
      expect(properties.sourceURL).toBe(fileURLToPath(new URL("../node_modules/@better-auth/utils/dist/otp.mjs", import.meta.url)));
      expect(expected.sourceURL.endsWith("/node_modules/@better-auth/utils/dist/otp.mjs")).toBe(true);
      properties.sourceURL = expected.sourceURL;
    }
  }
  expect(actual, `Capture evidence: ${directory}`).toStrictEqual(fixture);
  rmSync(directory, { recursive: true });
}, 60_000);
