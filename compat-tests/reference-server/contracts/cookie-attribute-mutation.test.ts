import { expect, test } from "bun:test";
import { captureCookieAttributeMutation } from "./cookie-attribute-mutation-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/cookie-attribute-mutation-1.7.6.json", import.meta.url)).text();

test("cookie attribute mutation capture retains complete ordered observations", async () => {
  const captured = await captureCookieAttributeMutation();
  expect(`${JSON.stringify(captured, null, 2)}\n`).toBe(fixture);
}, 60_000);
