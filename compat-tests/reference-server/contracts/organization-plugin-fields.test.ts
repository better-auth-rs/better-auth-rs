import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/organization-plugin-fields.json";
import { organizationPluginFields } from "./organization-plugin-fields";
import "./organization-team-member-contract";
import "./organization-team-details-contract";
import "./organization-team-member-duplicate-contract";
import "./organization-team-invitation-contract";
import "./organization-invitation-response-contract";

for (const backend of ["memory", "sqlite"] as const) {
  for (const order of ["before", "after"] as const) {
    test(`${backend} Organization fields follow plugin order: ${order}`, async () => {
      expect(await organizationPluginFields(backend, order)).toStrictEqual(
        expected.cases.find(value => value.backend === backend && value.order === order),
      );
    });
  }
}
