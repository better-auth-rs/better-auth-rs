import { expect, test } from "bun:test";
import { capturePaybin } from "./paybin";

const fixture = await Bun.file(new URL("../../../tests/fixtures/paybin-1.7.6.json", import.meta.url)).json();
const issuedAt = Math.floor(Date.now() / 1000);
const actual = await capturePaybin(issuedAt);

// Renew only issuance times so each signed fixture remains valid on later runs.
function fresh(value: any): any {
  if (Array.isArray(value)) return value.map(fresh);
  if (value === null || typeof value !== "object") return value;
  const result = Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fresh(item)]));
  if (result.iss === fixture.metadata.issuer && Object.hasOwn(result, "iat")) {
    result.iat = issuedAt;
    result.exp = issuedAt + 3600;
  }
  return result;
}
const expected = fresh(fixture);
expected.metadata.issuedAt = issuedAt;

test("Paybin uses the pinned Better Auth 1.7.6 contract", () => {
  expect(actual.metadata.version).toBe("1.7.6");
  expect(actual.metadata).toEqual(expected.metadata);
});
for (const section of ["scopeCases", "configurationErrors", "profileCases", "specialCases", "grants"] as const) {
  for (const sample of expected[section]) {
    const name = sample.name ?? sample.mode;
    test(`Paybin ${section}: ${name}`, () => {
      expect(actual[section].find((value: any) => (value.name ?? value.mode) === name)).toEqual(sample);
    });
  }
}
test("Paybin retains the custom refresh callback", () => {
  expect(actual.customRefresh).toEqual(expected.customRefresh);
});
