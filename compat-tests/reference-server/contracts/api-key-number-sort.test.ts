import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

test("Memory API Key number sorting preserves two-row numeric ties", async () => {
  const directory = mkdtempSync(join(tmpdir(), "better-auth-api-key-number-sort-"));
  const output = join(directory, "capture.json");
  const capture = fileURLToPath(new URL("./api-key-number-sort-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture, output], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  writeFileSync(join(directory, "stdout.log"), stdout);
  writeFileSync(join(directory, "stderr.log"), stderr);
  expect({ status, stderr }, `Capture evidence: ${directory}`).toEqual({ status: 0, stderr: "" });
  const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-number-sort-1.7.6.json", import.meta.url)).json();
  expect(JSON.parse(readFileSync(output, "utf8")), `Capture evidence: ${directory}`).toStrictEqual(fixture);
  rmSync(directory, { recursive: true });
}, 60_000);
