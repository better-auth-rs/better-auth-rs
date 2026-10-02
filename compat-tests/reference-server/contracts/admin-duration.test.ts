import { expect, test } from "bun:test";
import fixture from "../../../tests/fixtures/admin-duration-1.7.6.json";
import { capture } from "../../../tests/fixtures/admin-duration.capture.mjs";

for (const expected of fixture.cases) {
  test(`Admin ${expected.operation} duration ${expected.name}`, async () => {
    const { name, operation, configured, requested } = expected;
    const actual = await capture({ name, operation, configured, requested });
    expect(JSON.parse(JSON.stringify(actual))).toEqual(expected);
  });
}
