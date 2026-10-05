import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureOrganizationRoleServer } from "../contracts/organization-role-server-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} OrganizationRole columns and permission storage match upstream`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/organization-role-${backend}-server-1.7.6.json`, import.meta.url), "utf8"));
    expect(await captureOrganizationRoleServer(backend)).toEqual(fixture);
  });
}
