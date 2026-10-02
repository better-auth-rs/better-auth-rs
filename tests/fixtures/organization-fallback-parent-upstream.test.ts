import { expect, test } from "bun:test";
import expected from "./organization-fallback-parent-1.7.6.json";
import { capture, cases } from "./organization-fallback-parent.capture";

let index = 0;
for (const joins of [false, true]) for (const spec of cases) {
  const fixture = expected.cases[index++];
  test(`Memory joins=${joins} ${spec.path} ${spec.mode} parent display fields`, async () => {
    expect(await capture(joins, spec)).toStrictEqual(fixture);
  });
}
