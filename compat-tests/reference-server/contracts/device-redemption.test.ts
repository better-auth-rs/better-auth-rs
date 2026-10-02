import { expect, test } from "bun:test";
import { captureDeviceRedemption } from "./device-redemption";

const fixture = await Bun.file(new URL("../../../tests/fixtures/device-redemption-1.7.6.json", import.meta.url)).json();
const captured = await captureDeviceRedemption();

test("Device redemption capture uses pinned Better Auth 1.7.6", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured.version).toBe(fixture.version);
});

for (const result of captured.backends) {
  test(`${result.backend} server-only Device redemption preserves contexts and callback errors`, () => {
    expect(result).toStrictEqual(fixture.backends.find((value: { backend: string }) => value.backend === result.backend));
  });
}
