import { expect, test } from "bun:test";
import { captureDeviceReferenceDefaults } from "../contracts/device-reference-defaults-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`Device default Json and Date references preserve complete ${backend} operands and storage`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/device-reference-defaults-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await captureDeviceReferenceDefaults(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.backend).toBe(backend);
    expect(observed.idGeneration).toBe("default");
    expect(observed.groups.map(group => [group.ownerRefType, group.ownerId, group.serial, group.cases.length])).toStrictEqual([
      ["json", "ordinary-owner", false, 4], ["date", "1", false, 5],
    ]);
    expect(observed).toStrictEqual(fixture);
  });
}
