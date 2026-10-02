import { test } from "bun:test";

test("ordinary cookie HTTP serialization errors match the captured upstream contract", async () => {
  await import("./cookie-http-errors.mjs");
});
