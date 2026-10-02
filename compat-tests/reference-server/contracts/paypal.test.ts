import { expect, test } from "bun:test";
import { capturePayPal } from "./paypal.mjs";

test("PayPal ordinary contracts match pinned Better Auth 1.7.6", async () => {
  const core = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
  expect(core.version).toBe("1.7.6");
  const expected = await Bun.file(new URL("../../../tests/fixtures/paypal-1.7.6.json", import.meta.url)).json();
  expect(await capturePayPal()).toEqual(expected);
});
