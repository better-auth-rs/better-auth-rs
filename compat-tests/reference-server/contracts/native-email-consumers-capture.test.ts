import { test } from "bun:test";
import { expectStandaloneObservation } from "./standalone-capture";

test("native email consumers retain method results, identity, callback order and backend storage", async () => {
  await expectStandaloneObservation(
    new URL("./native-email-consumers-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/native-email-consumers-1.7.6.json", import.meta.url),
    "native-email-consumers",
  );
});
