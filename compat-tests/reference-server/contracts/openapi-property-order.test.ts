import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/openapi-property-order-1.7.6.json";
import { captureOpenApiPropertyOrder } from "./openapi-property-order";

test("OpenAPI generated field order preserves JavaScript keys and core plugin chronology", async () => {
  expect(await captureOpenApiPropertyOrder()).toStrictEqual(expected);
});
