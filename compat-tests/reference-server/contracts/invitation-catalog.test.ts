import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/invitation-catalog-1.7.6.json";
import { captureInvitationCatalog } from "./invitation-catalog";

test("Generated SQLite Invitation catalogs preserve complete physical metadata", async () => {
  expect(await captureInvitationCatalog()).toStrictEqual(expected);
});
