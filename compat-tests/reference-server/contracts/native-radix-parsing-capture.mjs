import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { assertSecondaryNativeVersions } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const wide = 1n << 60n;
const extended = 1n << 128n;
const overflow = (1n << 1024n) - (1n << 970n);
// BigInt constructs exact input strings. Only the runtime intrinsics produce observed numeric results.
const magnitudes = [
  ["safe-integer-last", (1n << 53n) - 1n],
  ["safe-integer-even-tie", (1n << 53n) + 1n],
  ["safe-integer-odd-tie", (1n << 53n) + 3n],
  ["lower-binade-tie", wide - 64n],
  ["wide-below-tie", wide + 127n],
  ["wide-even-tie", wide + 128n],
  ["wide-above-tie", wide + 129n],
  ["wide-odd-tie", wide + 384n],
  ["extended-below-tie", extended + (1n << 75n) - 1n],
  ["extended-even-tie", extended + (1n << 75n)],
  ["extended-sticky-bit", extended + (1n << 75n) + 1n],
  ["largest-finite", (1n << 1024n) - (1n << 971n)],
  ["overflow-below-tie", overflow - 1n],
  ["overflow-tie", overflow],
  ["overflow-above-tie", overflow + 1n],
  ["overflow-power", 1n << 1024n],
];

export const nativeRadixParsingCases = magnitudes.flatMap(([boundary, value]) => [
  { name: `${boundary}:decimal`, boundary, input: value.toString(10) },
  { name: `${boundary}:negative-decimal`, boundary, input: `-${value.toString(10)}` },
  { name: `${boundary}:hexadecimal`, boundary, input: `0x${value.toString(16)}` },
  { name: `${boundary}:negative-hexadecimal`, boundary, input: `-0x${value.toString(16)}` },
  { name: `${boundary}:binary`, boundary, input: `0b${value.toString(2)}` },
  { name: `${boundary}:octal`, boundary, input: `0o${value.toString(8)}` },
]);

nativeRadixParsingCases.push(...[
  ["empty", ""], ["whitespace", "\uFEFF \t\n\u00A0\u2029"], ["excluded-next-line", "\u00850x1"],
  ["hex-empty", "0x"], ["hex-negative-empty", "-0x"],
  ["hex-leading-zeroes", "0x0000001000000000000081"],
  ["hex-uppercase-plus", "+0X1000000000000081"],
  ["hex-whitespace-sign", "\uFEFF -0X1000000000000081\u00A0"],
  ["hex-invalid-tail", "0x1000000000000081g"],
  ["hex-fraction", "0x1000000000000081.8"],
  ["hex-exponent-digit", "0x1e3"], ["hex-binary-exponent", "0x1p4"],
  ["hex-separator", "0x1_0"], ["hex-negative-zero", "-0x0"], ["hex-default-vs-decimal", "0x10"],
  ["binary-lowercase", "0b101"], ["binary-uppercase", "0B101"],
  ["binary-invalid-tail", "0b1012"], ["binary-negative", "-0b101"], ["binary-empty", "0b"],
  ["octal-lowercase", "0o17"], ["octal-uppercase", "0O17"],
  ["octal-invalid-tail", "0o178"], ["octal-plus", "+0o17"], ["octal-empty", "0o"],
  ["decimal-leading-zero", "010"], ["decimal-exponent", "-12e4"],
  ["decimal-negative-zero", "-0"], ["decimal-negative-zero-tail", "-0tail"],
  ["decimal-fraction", ".5"], ["decimal-overflow-exponent", "1e309"],
  ["decimal-rounded-prefix", " -000544157599796692941tail"],
  ["decimal-overflow-digits", "9".repeat(400)],
  ["plus-only", "+"], ["minus-only", "-"], ["space-after-sign", "+ 0x10"],
  ["infinity", "Infinity"], ["nan", "NaN"], ["fullwidth-digit", "０x10"],
].map(([name, input]) => ({ name, boundary: "syntax", input })));

const operations = [
  ["inferred", "parseInt(input)", input => parseInt(input)],
  ["decimal", "parseInt(input, 10)", input => parseInt(input, 10)],
  ["number", "Number(input)", input => Number(input)],
];

function sourceProvenance() {
  return [
    ["better-auth/dist/plugins/email-otp/routes.mjs", "parseInt("],
    ["better-auth/dist/plugins/two-factor/otp/index.mjs", "parseInt("],
    ["better-auth/dist/plugins/organization/routes/crud-org.mjs", "parseInt("],
    ["@better-auth/core/dist/db/adapter/factory.mjs", "Number("],
  ].map(([path, expression]) => {
    const source = readFileSync(new URL(`../node_modules/${path}`, import.meta.url), "utf8");
    const calls = source.split("\n").flatMap((text, index) => text.includes(expression)
      ? [{ line: index + 1, source: text.trim() }] : []);
    assert.ok(calls.length > 0, `Missing numeric consumer in ${path}`);
    return { path, sha256: createHash("sha256").update(source).digest("hex"), calls };
  });
}

export function captureNativeRadixParsing() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  assert.equal(new Set(nativeRadixParsingCases.map(({ name }) => name)).size, nativeRadixParsingCases.length);
  const { observe } = createProtectedFunctionObserver();
  const cases = nativeRadixParsingCases.map(scenario => ({
    ...scenario,
    operations: operations.map(([name, source, operation]) => {
      const result = operation(scenario.input);
      const bits = new DataView(new ArrayBuffer(8));
      bits.setFloat64(0, result, false);
      return {
        name, source, result: Object.is(result, -0) ? { type: "number", value: "-0" } : observe(result),
        negativeZero: Object.is(result, -0),
        string: String(result), json: JSON.stringify(result),
        bits: bits.getBigUint64(0, false).toString(16).padStart(16, "0"),
      };
    }),
  }));
  return {
    contract: "native-radix-parsing", version: "1.7.6", runtime: { bun: Bun.version },
    provenance: sourceProvenance(),
    boundary: "Pinned Bun numeric intrinsics used by the recorded Better Auth consumers. BigInt constructs only inputs. Results retain finite values, signed zero, nonfinite values, decimal rendering, JSON rendering and all IEEE-754 bits. This capture does not execute full plugin or adapter lifecycles. NaN payload bits are retained as runtime evidence, not a portable ECMAScript numeric guarantee.",
    cases,
  };
}

if (import.meta.main) {
  assert.equal(process.argv.length, 3, "Pass the output path");
  const serialized = `${JSON.stringify(captureNativeRadixParsing(), null, 2)}\n`;
  writeFileSync(process.argv[2], serialized);
  await writeObservation(serialized);
}
