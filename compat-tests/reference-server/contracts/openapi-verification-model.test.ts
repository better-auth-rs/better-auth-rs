import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/openapi-verification-model-1.7.6.json";
import { captureOpenApiVerificationModel } from "./openapi-verification-model";

test("OpenAPI Verification metadata follows the final storage configuration", async () => {
  expect(await captureOpenApiVerificationModel()).toStrictEqual(expected);
});
