import { expect, test } from "bun:test";
import { assertApiKeyDateUsage, captureApiKeyDateUsage } from "../contracts/api-key-date-usage-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`API Key ${backend} Date usage preserves guards, milliseconds, rows and callback traces`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/api-key-date-usage-${backend}-1.7.6.json`, import.meta.url)).json();
    const diagnostics: unknown[] = [];
    try {
      const observed = await captureApiKeyDateUsage({ diagnostics, backends: [backend] });
      assertApiKeyDateUsage(observed, [backend]);
      expect(observed).toStrictEqual(fixture);
    } catch (error) {
      console.error(JSON.stringify(diagnostics, null, 2));
      throw error;
    }
  }, 60_000);
}
