import { expect, test } from "bun:test";
import { capturePasskeySharedDisplay } from "./passkey-shared-display-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/passkey-shared-display-1.7.6.json", import.meta.url)).json();

test("Passkey shared display columns preserve both declaration orders and HTTP updates", async () => {
  expect(await capturePasskeySharedDisplay()).toStrictEqual(fixture);
}, 60_000);
