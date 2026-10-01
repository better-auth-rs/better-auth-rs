import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { collectTelemetryOptions, fixturePath } from "./telemetry-options.mjs";

test("telemetry option projection matches the Rust fixture for Better Auth 1.7.6", async () => {
  const expected = JSON.parse(readFileSync(fixturePath, "utf8"));
  expect(await collectTelemetryOptions()).toEqual(expected);
});
