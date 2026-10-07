import { expect, test } from "bun:test";
import { captureOAuthTokenDuration } from "./oauth-token-duration-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/oauth-token-duration-1.7.6.json", import.meta.url)).text();

test("OAuth duration capture preserves complete helper, HTTP, callback, and storage observations", async () => {
  expect(`${JSON.stringify(await captureOAuthTokenDuration(), null, 2)}\n`).toBe(fixture);
}, 60_000);
