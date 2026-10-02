import { test, expect } from "bun:test";
import fixture from "./fallback-continuation-1.7.6.json";
import { capture } from "./fallback-continuation.capture";

for (const row of fixture.cases) {
  test(`${row.backend} ${row.kind} ${row.mode}: fallback continuation`, async () => {
    expect(await capture(row.backend, row.kind as "session" | "invitation", row.mode as Parameters<typeof capture>[2])).toEqual(row);
  });
}
