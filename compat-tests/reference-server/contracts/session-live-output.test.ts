import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureSessionLiveOutput } from "./session-live-output-capture.mjs";

test("Memory Session output keeps live rows and native join snapshots distinct", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/session-live-output-1.7.6.json", import.meta.url), "utf8"));
  const actual = await captureSessionLiveOutput();
  expect(actual).toStrictEqual(fixture);
  expect(actual.version).toBe("1.7.6");
  expect(actual.cases).toHaveLength(4);
}, 30_000);
