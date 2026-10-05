import { expect, test } from "bun:test";
import { captureOpenApiRateLimitModel } from "./openapi-rate-limit-model-capture.mjs";

test("database RateLimit metadata replaces plugin fields without moving the component", async () => {
  const expected = await Bun.file(new URL("../../../tests/fixtures/openapi-rate-limit-model-1.7.6.json", import.meta.url)).json();
  expect(await captureOpenApiRateLimitModel()).toStrictEqual(expected);
});
