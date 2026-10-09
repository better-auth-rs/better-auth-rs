import { expect } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

export async function expectStandaloneCapture(
  capture: URL,
  fixture: URL,
  args: readonly string[] = [],
): Promise<void> {
  const expected = readFileSync(fixture, "utf8");
  const script = fileURLToPath(capture);
  const directory = mkdtempSync(join(tmpdir(), `better-auth-${basename(script, ".mjs")}-`));
  const output = join(directory, "capture.json");
  // Bun's test runner exposes different Error properties from standalone captures.
  const env = { ...process.env };
  // The standalone capture has no test-mode IP fallback.
  delete env.NODE_ENV;
  delete env.TEST;
  const child = Bun.spawn([process.execPath, "--no-install", script, ...args, output], {
    stdout: "pipe", stderr: "pipe", env,
  });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  writeFileSync(join(directory, "stdout.log"), stdout);
  writeFileSync(join(directory, "stderr.log"), stderr);
  expect({ status, stderr }, `Capture evidence: ${directory}`).toEqual({ status: 0, stderr: "" });
  expect(readFileSync(output, "utf8"), `Capture evidence: ${directory}`).toBe(expected);
  rmSync(directory, { recursive: true });
}
