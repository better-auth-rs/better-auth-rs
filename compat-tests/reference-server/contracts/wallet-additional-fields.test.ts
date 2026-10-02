import { expect, test } from "bun:test";
import { captureWalletAdditionalFields } from "./wallet-additional-fields";

const fixture = await Bun.file(new URL("../../../tests/fixtures/wallet-additional-fields-1.7.6.json", import.meta.url)).json();
const captured = await captureWalletAdditionalFields();

test("Wallet display fields preserve the pinned adapter conversion and error phases", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured.cases).toHaveLength(6);
  expect(captured).toStrictEqual(fixture);
});
