import { expect, test } from "bun:test";
import { failureOperations, operationNames } from "./api-key-fields-capture.mjs";
import { captureApiKeyNameMapping, nameMappings } from "./api-key-name-mapping-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-name-mapping-1.7.6.json", import.meta.url)).json();

test("API Key name mappings preserve complete rows, physical columns, usage guards, callbacks and original errors", async () => {
  const captured = await captureApiKeyNameMapping();
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) {
    expect(backend.cases.map(({ mapping }: { mapping: string }) => mapping)).toStrictEqual(nameMappings);
    for (const scenario of backend.cases) {
      expect(scenario.operations.map(({ name }: { name: string }) => name)).toStrictEqual(operationNames);
      expect(scenario.failures.map(({ name }: { name: string }) => name)).toStrictEqual(
        failureOperations.flatMap((operation: string) => (operation === "decrement" ? ["output"] : ["input", "output"]).map(phase => `${operation}-${phase}-error`)),
      );
    }
  }
  expect(captured).toStrictEqual(fixture);
});
