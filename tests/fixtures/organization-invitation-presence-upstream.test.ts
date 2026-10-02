import { expect, test } from "bun:test";
import fixture from "./organization-invitation-presence-1.7.6.json";
import { capture } from "./organization-invitation-presence.capture";

for (const row of fixture.cases) {
  test(`${row.backend} ${row.mode}: invitation field presence`, async () => {
    expect(await capture(row.backend as Parameters<typeof capture>[0], row.mode as Parameters<typeof capture>[1])).toStrictEqual(row);
  });
}
