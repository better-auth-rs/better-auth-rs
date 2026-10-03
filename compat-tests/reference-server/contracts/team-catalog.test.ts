import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/team-catalog-1.7.6.json";
import { captureTeamCatalog } from "./team-catalog";

test("Generated SQLite Team catalogs preserve complete physical metadata", async () => {
  expect(await captureTeamCatalog()).toStrictEqual(expected);
});
