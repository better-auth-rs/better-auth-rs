import { expect, test } from "bun:test";
import { captureDeviceWhereReferences } from "../contracts/device-where-references-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`Device String-ID references retain complete ${backend} bindings, callbacks, storage and rollback`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/device-where-references-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await captureDeviceWhereReferences(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.idGeneration).toBe("default");
    expect(observed.groups.flatMap(group => group.cases)).toHaveLength(18);
    expect(observed).toStrictEqual(fixture);
  });
}
