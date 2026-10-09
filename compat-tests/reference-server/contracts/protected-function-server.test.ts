import { expect, test } from "bun:test";
import { captureProtectedFunctionServer } from "./protected-function-server-capture.mjs";

for (const backend of ["postgres", "mysql"] as const) {
  test(`${backend} protected functions preserve complete schema, callbacks, storage and transaction observations`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/protected-function-${backend}-1.7.6.json`, import.meta.url)).text();
    expect(`${JSON.stringify(await captureProtectedFunctionServer(backend), null, 2)}\n`).toBe(fixture);
  }, 120_000);
}
