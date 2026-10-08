import { expect, test } from "bun:test";
import { captureDeviceGrantSql } from "../contracts/device-grant-sql-capture.mjs";

for (const backend of ["sqlite", "postgres", "mysql"]) {
  test(`Device grant ${backend} preserves lifecycles, callback failures and storage`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/device-grant-sql-${backend}-1.7.6.json`, import.meta.url)).json();
    const diagnostics: unknown[] = [];
    try {
      expect(await captureDeviceGrantSql(backend, { diagnostics })).toStrictEqual(fixture);
    } catch (error) {
      console.error(JSON.stringify(diagnostics, null, 2));
      throw error;
    }
  }, 60_000);
}
