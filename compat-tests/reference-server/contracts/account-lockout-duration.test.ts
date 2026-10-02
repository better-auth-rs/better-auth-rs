import { expect, test } from "bun:test";
import fixture from "../../../tests/fixtures/account-lockout-duration-1.7.6.json";
import { capture } from "../../../tests/fixtures/account-lockout-duration.capture.mjs";

for (const expected of fixture.cases) {
  test(`AccountLockout durationSeconds ${expected.name}`, async () => {
    const actual = await capture(expected.name, expected.configured ?? undefined);
    expect(actual).toEqual(expected);
  });
}
