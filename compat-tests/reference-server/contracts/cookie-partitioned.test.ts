import { test } from "bun:test";

test("ordinary secure cookie partitioning matches the captured contract", async () => {
  await import("./cookie-partitioned.mjs");
});
