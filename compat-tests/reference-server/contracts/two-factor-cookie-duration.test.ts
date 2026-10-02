import { expect, test } from "bun:test";
import fixture from "../../../tests/fixtures/two-factor-cookie-duration-1.7.6.json";
import { capture } from "../../../tests/fixtures/two-factor-cookie-duration.capture.mjs";

for (const expected of fixture.cases) {
  test(`Two Factor ${expected.operation} cookie lifetime ${expected.name}`, async () => {
    const actual = await capture(expected.name, expected.configured, expected.operation);
    expect(JSON.parse(JSON.stringify(actual))).toEqual(expected);
  });
}
