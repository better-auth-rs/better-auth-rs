import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { captureSessionServer } from "../contracts/session-server-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} Session storage and columns match upstream`, async () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../../tests/fixtures/session-${backend}-server-1.7.6.json`, import.meta.url), "utf8"));
    expect(await captureSessionServer(backend)).toEqual(fixture);
  });
}
