import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureServerCatalog } from "../contracts/server-catalog-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} User and Account schema matches the pinned catalog`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/user-account-${backend}-catalog-1.7.6.json`, import.meta.url), "utf8"));
    expect(await captureServerCatalog(backend)).toEqual(fixture);
  });
}
