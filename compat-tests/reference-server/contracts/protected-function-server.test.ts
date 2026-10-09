import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

for (const backend of ["postgres", "mysql"] as const) {
  test(`${backend} protected functions preserve complete schema, callbacks, storage and transaction observations`, async () => {
    await expectStandaloneCapture(
      new URL("./protected-function-server-capture.mjs", import.meta.url),
      new URL(`../../../tests/fixtures/protected-function-${backend}-1.7.6.json`, import.meta.url),
      [backend],
    );
  }, 120_000);
}
