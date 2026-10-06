import { expect, test } from "bun:test";
import { capturePasskeyFields } from "./passkey-fields-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/passkey-fields-1.7.6.json", import.meta.url)).json();

test("Passkey additional fields preserve complete operations, stored rows, callback traces and original errors", async () => {
  const captured = await capturePasskeyFields();
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) {
    expect(backend.operations.map(({ name }: { name: string }) => name)).toStrictEqual([
      "create", "get-id", "get-credential", "list", "update-name", "update-auth",
    ]);
    expect(backend.failures.map(({ name }: { name: string }) => name)).toStrictEqual([
      "create-input-error", "create-output-error", "update-name-input-error", "update-name-output-error", "update-auth-input-error", "update-auth-output-error",
    ]);
  }
  expect(captured).toStrictEqual(fixture);
});
