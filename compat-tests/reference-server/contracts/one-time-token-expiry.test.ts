import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import fixture from "../../../tests/fixtures/one-time-token-expiry-1.7.6.json";

test("One Time Token expiry precedes custom hashing for HTTP generation and set-ott", async () => {
  const directory = mkdtempSync(join(tmpdir(), "better-auth-one-time-token-expiry-"));
  const output = join(directory, "capture.json");
  const capture = fileURLToPath(new URL("./one-time-token-expiry-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture, output], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  writeFileSync(join(directory, "stdout.log"), stdout);
  writeFileSync(join(directory, "stderr.log"), stderr);
  expect({ status, stderr }, `Capture evidence: ${directory}`).toEqual({ status: 0, stderr: "" });
  const actual = JSON.parse(readFileSync(output, "utf8"));
  expect(actual, `Capture evidence: ${directory}`).toStrictEqual(fixture);
  rmSync(directory, { recursive: true });
}, 60_000);
