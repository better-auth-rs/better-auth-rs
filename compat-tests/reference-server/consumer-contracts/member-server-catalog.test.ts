import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureMemberServerCatalog } from "../contracts/member-server-catalog-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} Member schema matches the pinned default and mapped catalogs`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/member-${backend}-catalog-1.7.6.json`, import.meta.url), "utf8"));
    expect(await captureMemberServerCatalog(backend)).toEqual(fixture);
  });
}
