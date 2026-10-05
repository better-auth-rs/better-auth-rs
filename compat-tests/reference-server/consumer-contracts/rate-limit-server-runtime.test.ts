import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureRateLimitServerRuntime } from "../contracts/rate-limit-server-runtime-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} RateLimit ordinary counter lifecycle matches upstream`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/rate-limit-${backend}-runtime-1.7.6.json`, import.meta.url), "utf8"));
    expect(await captureRateLimitServerRuntime(backend)).toEqual(fixture);
  });
}
