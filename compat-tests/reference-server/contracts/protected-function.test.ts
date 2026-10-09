import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { captureProtectedFunction } from "./protected-function-capture.mjs";

test("protected function input preserves complete presence, identity, callback and error observations", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/protected-function-input-1.7.6.json", import.meta.url)).text();
  const directory = mkdtempSync(join(tmpdir(), "better-auth-protected-function-input-"));
  const output = join(directory, "capture.json");
  const capture = fileURLToPath(new URL("./protected-function-input-capture.mjs", import.meta.url));
  // Bun's test runner adds Error properties that the captured standalone process does not expose.
  const child = Bun.spawn([process.execPath, "--no-install", capture, output], {
    stdout: "pipe", stderr: "pipe",
  });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  writeFileSync(join(directory, "stdout.log"), stdout);
  writeFileSync(join(directory, "stderr.log"), stderr);
  expect({ status, stderr }, `Capture evidence: ${directory}`).toEqual({ status: 0, stderr: "" });
  expect(readFileSync(output, "utf8"), `Capture evidence: ${directory}`).toBe(fixture);
  rmSync(directory, { recursive: true });
});

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} protected functions preserve complete callbacks, storage, transactions and public output`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/protected-function-${backend}-1.7.6.json`, import.meta.url)).text();
    expect(`${JSON.stringify(await captureProtectedFunction(backend), null, 2)}\n`).toBe(fixture);
  }, 60_000);
}
