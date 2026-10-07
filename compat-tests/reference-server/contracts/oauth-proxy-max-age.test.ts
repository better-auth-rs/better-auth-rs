import { expect, test } from "bun:test";
import { captureOAuthProxyMaxAge } from "./oauth-proxy-max-age-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/oauth-proxy-max-age-1.7.6.json", import.meta.url)).text();

test("OAuth Proxy maxAge matches every captured HTTP lifecycle and millisecond boundary", async () => {
  expect(`${JSON.stringify(await captureOAuthProxyMaxAge(), null, 2)}\n`).toBe(fixture);
}, 60_000);
