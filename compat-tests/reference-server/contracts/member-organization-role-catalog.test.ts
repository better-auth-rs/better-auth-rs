import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/member-organization-role-catalog-1.7.6.json";
import { captureMemberOrganizationRoleCatalog } from "./member-organization-role-catalog";

test("Generated SQLite Member and OrganizationRole catalogs preserve complete physical metadata", async () => {
  expect(await captureMemberOrganizationRoleCatalog()).toStrictEqual(expected);
});
