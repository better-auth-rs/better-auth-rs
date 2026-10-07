import { expect, test } from "bun:test";
import { captureDeviceReferenceValues } from "../contracts/device-reference-values-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`Device Json and Date references preserve complete ${backend} binding, guards and rollback`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/device-reference-values-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await captureDeviceReferenceValues(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.backend).toBe(backend);
    expect(observed.groups.map(group => [group.ownerRefType, group.serial, group.cases.length])).toStrictEqual([["json", true, 12], ["date", true, 12]]);
    expect(observed).toStrictEqual(fixture);
  });
}
