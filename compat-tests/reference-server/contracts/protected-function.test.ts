import { expect, test } from "bun:test";
import { captureProtectedFunction } from "./protected-function-capture.mjs";
import { expectStandaloneCapture } from "./standalone-capture";

test("protected function input preserves complete presence, identity, callback and error observations", async () => {
  await expectStandaloneCapture(
    new URL("./protected-function-input-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/protected-function-input-1.7.6.json", import.meta.url),
  );
});

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} protected functions preserve complete callbacks, storage, transactions and public output`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/protected-function-${backend}-1.7.6.json`, import.meta.url)).text();
    expect(`${JSON.stringify(await captureProtectedFunction(backend), null, 2)}\n`).toBe(fixture);
  }, 60_000);
}
