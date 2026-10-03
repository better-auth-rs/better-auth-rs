import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/jwk-rate-limit-catalog-1.7.6.json";
import { captureJwkRateLimitCatalog } from "./jwk-rate-limit-catalog";

test("Generated SQLite JWK and RateLimit catalogs preserve complete physical metadata", async () => {
  expect(await captureJwkRateLimitCatalog()).toStrictEqual(expected);
});
