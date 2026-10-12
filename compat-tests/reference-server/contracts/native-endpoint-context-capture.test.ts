import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("native endpoint roots preserve full own descriptors and helper identities", async () => {
  await expectStandaloneCapture(
    new URL("./native-endpoint-context-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/native-endpoint-context-1.7.6.json.gz", import.meta.url),
  );
});
