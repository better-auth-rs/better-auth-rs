import { expect, test } from "bun:test";
import { capturePluginOutputCapabilities, modelNames, observationNames } from "./plugin-output-capabilities-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/plugin-output-capabilities-1.7.6.json", import.meta.url)).json();

test("plugin output callbacks preserve backend representations, decoding order, complete rows and original errors", async () => {
  const captured = await capturePluginOutputCapabilities();
  expect(captured.version).toBe("1.7.6");
  expect(captured.backends.map(({ backend }: { backend: string }) => backend)).toStrictEqual(["memory", "sqlite"]);
  for (const backend of captured.backends) {
    expect(backend.models.map(({ model }: { model: string }) => model)).toStrictEqual(modelNames);
    for (const model of backend.models) {
      expect(model.observations.map(({ name }: { name: string }) => name)).toStrictEqual(observationNames);
    }
  }
  expect(captured).toStrictEqual(fixture);
});
