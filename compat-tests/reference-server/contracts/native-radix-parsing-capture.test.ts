import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("native radix parsing preserves integer rounding, prefixes, signed zero and overflow", async () => {
  await expectStandaloneObservation(
    new URL("./native-radix-parsing-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/native-radix-parsing-1.7.6.json", import.meta.url),
    "native-radix-parsing",
  );
});
