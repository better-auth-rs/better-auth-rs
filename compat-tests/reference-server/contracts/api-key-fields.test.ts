import { expect, test } from "bun:test";
import { captureApiKeyFields, failureOperations, operationNames } from "./api-key-fields-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-fields-1.7.6.json", import.meta.url)).json();

test("API Key additional fields preserve complete rows, usage guards, callback traces and original errors", async () => {
  const captured = await captureApiKeyFields();
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) {
    expect(backend.operations.map(({ name }: { name: string }) => name)).toStrictEqual(operationNames);
    expect(backend.failures.map(({ name }: { name: string }) => name)).toStrictEqual(
      failureOperations.flatMap((operation: string) => (operation === "decrement" ? ["output"] : ["input", "output"]).map(phase => `${operation}-${phase}-error`)),
    );
  }
  expect(captured).toStrictEqual(fixture);
});
