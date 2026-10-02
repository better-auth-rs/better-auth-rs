import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/organization-serial-references-1.7.6.json";
import { captureOrganizationSerialReferences } from "./organization-serial-references";

test("Organization Memory references preserve ordinary Serial fields and lifecycle results", async () => {
  expect(await captureOrganizationSerialReferences()).toStrictEqual(expected);
});
