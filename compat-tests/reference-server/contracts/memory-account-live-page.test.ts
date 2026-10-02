import { expect, test } from "bun:test";
import fixture from "../../../tests/fixtures/memory-account-live-page-1.7.6.json";
import { capture } from "../../../tests/fixtures/memory-account-live-page.capture.mjs";

for (const expected of fixture.cases) {
  test(`Memory account page joins=${expected.joins} keeps later display values live`, async () => {
    expect(await capture(expected.joins)).toEqual(expected);
  });
}
