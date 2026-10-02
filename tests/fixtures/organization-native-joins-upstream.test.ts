import { expect, test } from "bun:test";
import expected from "./organization-native-joins-1.7.6.json";
import { capture, cases } from "./organization-native-joins.capture";

let index = 0;
for (const backend of ["memory", "sqlite"]) for (const joins of [false, true]) {
  for (const spec of cases) {
    const fixture = expected.cases[index++];
    test(`${backend} joins=${joins} ${spec.path} ${spec.mode} limit=${spec.limit} members=${spec.membersLimit ?? "default"} teams=${spec.includeTeams ?? true}`, async () => {
      expect(await capture(backend, joins, spec)).toStrictEqual(fixture);
    });
  }
}

import unconfigured from "./organization-native-joins-unconfigured-1.7.6.json";
for (const fixture of unconfigured.cases) {
  test(`${fixture.backend} joins=${fixture.joins} unconfigured native logo phase`, async () => {
    expect(await capture(fixture.backend, fixture.joins, {
      path: "organizations", mode: "parent-read", limit: 2, unconfiguredLogo: true,
    })).toStrictEqual(fixture);
  });
}
