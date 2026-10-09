import { expect, test } from "bun:test";
import { captureProtectedFunctionInput } from "./protected-function-input-capture.mjs";
import { captureProtectedFunction } from "./protected-function-capture.mjs";

test("protected function input preserves complete presence, identity, callback and error observations", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/protected-function-input-1.7.6.json", import.meta.url)).text();
  expect(`${JSON.stringify(captureProtectedFunctionInput(), null, 2)}\n`).toBe(fixture);
});

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} protected functions preserve complete callbacks, storage, transactions and public output`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/protected-function-${backend}-1.7.6.json`, import.meta.url)).text();
    expect(`${JSON.stringify(await captureProtectedFunction(backend), null, 2)}\n`).toBe(fixture);
  }, 60_000);
}
