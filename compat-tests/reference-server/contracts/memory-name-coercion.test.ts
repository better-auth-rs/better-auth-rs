import { expect, test } from "bun:test";
import { captureMemoryNameCoercion } from "./memory-name-coercion-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/memory-name-coercion-1.7.6.json", import.meta.url)).text();

test("Memory name conversion retains complete values, callbacks and stored rows", async () => {
  expect(`${JSON.stringify(await captureMemoryNameCoercion(), null, 2)}\n`).toBe(fixture);
}, 60_000);
