import { expect, test } from "bun:test";
import { captureDeviceScope } from "./device-scope";

const fixture = await Bun.file(new URL("../../../tests/fixtures/device-scope-1.7.6.json", import.meta.url)).json();
const captured = await captureDeviceScope();

test("DeviceCode scope capture uses pinned Better Auth 1.7.6", () => {
  expect(captured.version).toBe("1.7.6");
  expect(captured.version).toBe(fixture.version);
});

for (const result of captured.backends) {
  test(`${result.backend} DeviceCode scope policies match ordinary captured lifecycle results`, () => {
    expect(result).toEqual(fixture.backends.find((value: { backend: string }) => value.backend === result.backend));
  });
}
