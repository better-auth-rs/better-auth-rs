import { expect, test } from "bun:test";
import expected from "./organization-join-continuation-1.7.6.json";
import { capture, observations } from "./organization-join-continuation.capture";

for (const fixture of expected.cases) {
  test(`${fixture.backend} ${fixture.kind} fallback join ${fixture.mode}`, async () => {
    await capture(fixture.backend, fixture.kind as "organization" | "team", fixture.mode as Parameters<typeof capture>[2]);
    expect(observations.at(-1)).toStrictEqual(fixture);
  });
}
