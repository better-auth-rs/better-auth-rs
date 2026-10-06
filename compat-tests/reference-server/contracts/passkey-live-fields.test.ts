import { expect, test } from "bun:test";
import { capturePasskeyLiveFields } from "./passkey-live-fields-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/passkey-live-fields-1.7.6.json", import.meta.url)).json();

test("Passkey output callbacks preserve live Memory fields, SQLite snapshots, row selection and original errors", async () => {
  const captured = await capturePasskeyLiveFields();
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) expect(backend.cases).toHaveLength(9);
  expect(captured).toStrictEqual(fixture);
});
