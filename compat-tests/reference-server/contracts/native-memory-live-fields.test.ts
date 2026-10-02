import { expect, test } from "bun:test";
import fixture from "../../../tests/fixtures/native-memory-live-fields-1.7.6.json";
import { capture } from "../../../tests/fixtures/native-memory-live-fields.capture.mjs";

for (const expected of fixture.cases) {
  test(`native Memory ${expected.path} reads later display fields after callback writes`, async () => {
    expect(await capture(expected.path)).toEqual(expected);
  });
}
