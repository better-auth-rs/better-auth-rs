import { test } from "bun:test";
import { expectStandaloneCapture } from "./standalone-capture";

test("API Key public rate-limit denial preserves its response and cache", async () => {
  await expectStandaloneCapture(
    new URL("./api-key-rate-limit-public-capture.mjs", import.meta.url),
    new URL("../../../tests/fixtures/api-key-rate-limit-public-1.7.6.json", import.meta.url),
  );
});
