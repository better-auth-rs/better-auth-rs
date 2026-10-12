import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("array cloning preserves captured length and live own-index selection", async () => {
  await expectStandaloneCapture(
    new URL("./native-property-clone-array-boundaries-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/native-property-clone-array-boundaries-1.7.6.json", import.meta.url),
  );
});
