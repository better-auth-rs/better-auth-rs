import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("native property transitions preserve flags, callback identity and partial deletion", async () => {
  await expectStandaloneCapture(
    new URL("./native-property-transition-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/native-property-transition-1.7.6.json", import.meta.url),
  );
});
