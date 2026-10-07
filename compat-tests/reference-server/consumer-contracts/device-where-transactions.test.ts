import { expect, test } from "bun:test";
import { captureDeviceWhereTransactions } from "../contracts/device-where-transactions-capture.mjs";

for (const backend of ["postgres", "mysql"]) {
  test(`Device Where retains ${backend} values across transaction copies and reads`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/device-where-transactions-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await captureDeviceWhereTransactions(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.groups.flatMap(group => group.cases)).toHaveLength(23);
    expect(observed).toStrictEqual(fixture);
  });
}
