import { expect, test } from "bun:test";
import { passkey } from "@better-auth/passkey";
import { withRestoredSchema } from "./schema-isolation.mjs";
import { capturePasskeyDisplayMapping, mappingNames } from "./passkey-display-mapping-capture.mjs";
import { passkeyFailureOperations, passkeyOperationNames } from "./passkey-fields-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/passkey-display-mapping-1.7.6.json", import.meta.url)).json();

test("Passkey display policies preserve native field mappings, complete rows, callback order and original errors", async () => {
  const schema = passkey().schema;
  const before = Object.fromEntries(Object.entries(schema).map(([name, model]) => [name, {
    ...model, fields: Object.fromEntries(Object.entries(model.fields).map(([field, attributes]) => [field, { ...attributes }])),
  }]));
  const captured = await capturePasskeyDisplayMapping();
  expect(schema).toStrictEqual(before);
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) {
    expect(backend.cases.map(({ mapping }: { mapping: string }) => mapping)).toStrictEqual(mappingNames);
    for (const mapping of backend.cases) {
      expect(mapping.operations.map(({ name }: { name: string }) => name)).toStrictEqual(passkeyOperationNames);
      expect(mapping.failures.map(({ name }: { name: string }) => name)).toStrictEqual(
        passkeyFailureOperations.flatMap((operation: string) => ["input", "output"].map(phase => `${operation}-${phase}-error`)),
      );
    }
  }
  expect(captured).toStrictEqual(fixture);
  const failure = new Error("Capture failed after applying a schema mapping");
  await expect(withRestoredSchema(schema, async () => {
    passkey({ schema: { passkey: { modelName: "failed_capture", fields: { name: "failed_name" } } } });
    throw failure;
  })).rejects.toBe(failure);
  expect(schema).toStrictEqual(before);
});
