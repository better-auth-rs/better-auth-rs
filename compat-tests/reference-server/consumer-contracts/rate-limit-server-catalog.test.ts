import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureRateLimitServerCatalog } from "../contracts/rate-limit-server-catalog-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} RateLimit schema matches the pinned default and mapped catalogs`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/rate-limit-${backend}-catalog-1.7.6.json`, import.meta.url), "utf8"));
    expect(await captureRateLimitServerCatalog(backend)).toEqual(fixture);
  });
}
