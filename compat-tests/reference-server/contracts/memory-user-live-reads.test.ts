import { expect, test } from "bun:test";
import fixture from "../../../tests/fixtures/memory-user-live-reads-1.7.6.json";
import { capture } from "../../../tests/fixtures/memory-user-live-reads.capture.mjs";

for (const expected of fixture.cases) {
  test(`Memory ${expected.path} joins=${expected.joins} reads live display fields`, async () => {
    expect(await capture(expected.path, expected.joins)).toEqual(expected);
  });
}
