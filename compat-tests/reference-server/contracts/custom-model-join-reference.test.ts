import { expect, test } from "bun:test";
import { captureCustomModelJoinReferences } from "./custom-model-join-reference-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/custom-model-join-reference-1.7.6.json", import.meta.url)).text();

test("custom model references retain complete joined observations and native guards", async () => {
  expect(`${JSON.stringify(await captureCustomModelJoinReferences(), null, 2)}\n`).toBe(fixture);
}, 60_000);
