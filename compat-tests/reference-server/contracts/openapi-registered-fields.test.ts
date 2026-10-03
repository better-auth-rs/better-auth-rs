import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/openapi-registered-fields-1.7.6.json";
import { captureOpenApiRegisteredFields } from "./openapi-registered-fields";

test("registered field policies reach complete OpenAPI components without callbacks", async () => {
  const actual = await captureOpenApiRegisteredFields();
  expect(actual).toStrictEqual(expected);
  expect(actual.cases.map(({ name }) => name)).toStrictEqual([
    "registered-only", "organization-before", "organization-after", "organization-disabled",
  ]);
  for (const { callbackCalls } of actual.cases) {
    expect(callbackCalls).toStrictEqual({ default: 0, input: 0, output: 0 });
  }
});
