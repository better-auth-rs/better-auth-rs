import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureVerificationServerCatalog } from "../contracts/verification-server-catalog-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} Verification schema matches the pinned default and mapped catalogs`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/verification-${backend}-catalog-1.7.6.json`, import.meta.url), "utf8"));
    expect(await captureVerificationServerCatalog(backend)).toEqual(fixture);
  });
}
