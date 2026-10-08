import { expect, test } from "bun:test";
import { assertApiKeyDateUsage, captureApiKeyDateUsage } from "./api-key-date-usage-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-date-usage-1.7.6.json", import.meta.url)).json();

test("API Key Date usage preserves exact guards, millisecond writes, complete rows and callback traces", async () => {
  const diagnostics: unknown[] = [];
  try {
    const captured = await captureApiKeyDateUsage({ diagnostics });
    assertApiKeyDateUsage(captured);
    expect(captured).toStrictEqual(fixture);
  } catch (error) {
    console.error(JSON.stringify(diagnostics, null, 2));
    throw error;
  }
});
