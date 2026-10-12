import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("native property cloning preserves selection, callback order and retained mutations", async () => {
  await expectStandaloneCapture(
    new URL("./native-property-clone-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/native-property-clone-1.7.6.json", import.meta.url),
  );
});
