import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/openapi-declaration-order-1.7.6.json";
import { captureOpenApiDeclarationOrder } from "./openapi-declaration-order";

test("registered field order follows the configured plugin order", async () => {
  const actual = await captureOpenApiDeclarationOrder();
  expect(actual).toStrictEqual(expected);
  expect(actual.cases.map(({ name, component }) => ({ name, required: component.required })))
    .toStrictEqual([
      {
        name: "custom-before-device",
        required: ["id", "label", "deviceCode", "userCode", "expiresAt", "status"],
      },
      {
        name: "device-before-custom",
        required: ["id", "deviceCode", "userCode", "expiresAt", "status", "label"],
      },
    ]);
});
