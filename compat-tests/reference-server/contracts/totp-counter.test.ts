import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import fixture from "../../../tests/fixtures/totp-counter-1.7.6.json";

function outcomes(entry) {
  return [entry.server, entry.helper.generation, entry.helper.uri,
    ...[...entry.helper.neighbors, ...entry.helper.bigintNeighbors].flatMap(neighbor => [neighbor.hotp, neighbor.verification]),
    entry.helper.malformed.verification];
}

test("TOTP counters retain Number window offsets and unsigned wrapping", async () => {
  const directory = mkdtempSync(join(tmpdir(), "better-auth-totp-counter-"));
  const output = join(directory, "capture.json");
  const capture = fileURLToPath(new URL("./totp-counter-capture.mjs", import.meta.url));
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
    const expected = outcomes(fixture.cases[index]);
    for (const [operation, result] of outcomes(entry).entries()) {
      if (result.kind !== "thrown") continue;
      const properties = result.error.properties;
      const reference = expected[operation].error.properties;
      // Validate the dependency module before mapping the checkout location.
      expect(properties.sourceURL).toBe(fileURLToPath(new URL("../node_modules/@better-auth/utils/dist/otp.mjs", import.meta.url)));
      expect(reference.sourceURL.endsWith("/node_modules/@better-auth/utils/dist/otp.mjs")).toBe(true);
      properties.sourceURL = reference.sourceURL;
    }
  }
  expect(actual, `Capture evidence: ${directory}`).toStrictEqual(fixture);
  rmSync(directory, { recursive: true });
}, 60_000);
