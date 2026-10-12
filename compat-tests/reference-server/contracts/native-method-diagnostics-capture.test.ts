import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("native method diagnostics retain complete errors, getters and value descriptors", async () => {
  await expectStandaloneObservation(
    new URL("./native-method-diagnostics-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/native-method-diagnostics-1.7.6.json", import.meta.url),
    "native-method-diagnostics",
    new Set(Array.from({ length: 34 }, (_, index) => `/cases/${index}/error/properties/sourceURL`)),
  );
});
