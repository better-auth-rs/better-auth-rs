import { expect, test } from "bun:test";
import expected from "./account-owner-multiple-fields-1.7.6.json";
import { capture } from "./account-owner-multiple-fields.capture";
for (const fixture of expected) {
  test(`${fixture.backend} ordinary account join projects both user display fields`, async () => {
    expect(await capture(fixture.backend)).toStrictEqual(fixture);
  });
}
