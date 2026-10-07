import { expect, test } from "bun:test";
import { captureDeviceReferenceSets } from "./device-reference-sets-capture.mjs";

for (const backend of ["memory", "sqlite"]) {
  test(`Device reference candidate sets retain complete ${backend} outcomes, guards and rollback`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/device-reference-sets-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await captureDeviceReferenceSets(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.backend).toBe(backend);
    expect(observed.groups.map(group => [group.serial, group.cases.length])).toStrictEqual([[false, 20], [true, 10]]);
    expect(observed).toStrictEqual(fixture);
  });
}
