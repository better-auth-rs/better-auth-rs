import { expect, test } from "bun:test";
import { captureWalletTransactionFields } from "./wallet-transaction-fields";

const fixture = await Bun.file(new URL("../../../tests/fixtures/wallet-transaction-fields-1.7.6.json", import.meta.url)).json();
const captured = await captureWalletTransactionFields();

test("Wallet display transactions preserve pinned commit and callback rollback", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured.cases).toHaveLength(4);
  expect(captured).toStrictEqual(fixture);
});
