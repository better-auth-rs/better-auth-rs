import { expect, test } from "bun:test";
import expected from "../../../tests/fixtures/admin-update-cancel-1.7.6.json";
import { captureAdminUpdateCancellation } from "../../../tests/fixtures/admin-update-cancel.capture.mjs";

test("ordinary Admin display updates preserve success, cancellation and original hook errors", async () => {
  expect(await captureAdminUpdateCancellation()).toStrictEqual(expected);
});
