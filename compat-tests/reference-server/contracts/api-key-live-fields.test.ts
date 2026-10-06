import { expect, test } from "bun:test";
import { captureApiKeyLiveFields } from "./api-key-live-fields-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-live-fields-1.7.6.json", import.meta.url)).json();

test("API Key name callbacks expose later native and additional fields with each adapter's read semantics", async () => {
  const captured = await captureApiKeyLiveFields();
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) expect(backend.cases.map(({ failOutput }: { failOutput: boolean }) => failOutput)).toStrictEqual([false, true]);
  expect(captured).toStrictEqual(fixture);
});
