import { expect, test } from "bun:test";
import { captureNativeJsonDriver } from "../contracts/native-json-driver-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`${backend} native JSON preserves every result, callback, diagnostic and stored value`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/native-json-driver-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await captureNativeJsonDriver(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.cases).toHaveLength(10);
    expect(observed).toStrictEqual(fixture);
  });
}
