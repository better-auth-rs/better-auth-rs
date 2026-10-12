import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("API Key rate-limit decisions preserve conversion order and backend writes", async () => {
  await expectStandaloneCapture(
    new URL("./api-key-rate-limit-native-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/api-key-rate-limit-native-1.7.6.json", import.meta.url),
  );
});
