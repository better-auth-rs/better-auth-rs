import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/openapi-jwks-1.7.6.json";
import { captureOpenApiJwks } from "./openapi-jwks";

test("OpenAPI preserves the complete JWKS operation at the configured path", async () => {
  expect(await captureOpenApiJwks()).toStrictEqual(expected);
});
