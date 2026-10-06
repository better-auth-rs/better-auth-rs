import { expect, test } from "bun:test";
import { captureDeviceWhere } from "./device-where-capture.mjs";

for (const backend of ["memory", "sqlite"]) {
  test(`Device Where preserves complete ${backend} query results, errors, callbacks and raw storage`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/device-where-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await captureDeviceWhere(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.groups.flatMap(group => group.cases)).toHaveLength(90);
    expect(observed).toStrictEqual(fixture);
  });
}
