import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const factories = [
  ["undefined", () => undefined], ["null", () => null], ["false", () => false], ["true", () => true],
  ["zero", () => 0], ["negative-zero", () => -0], ["number", () => 17], ["nan", () => NaN],
  ["infinity", () => Infinity], ["negative-infinity", () => -Infinity], ["string", () => "text"],
  ["empty-string", () => ""], ["escaped-string", () => 'quote"\nline'], ["object", () => ({ marker: "object" })],
  ["array", () => [1, 2]], ["date", () => new Date(secondaryNativeNow)], ["invalid-date", () => new Date(NaN)],
];
const calls = [
  { member: "receiver.split", source: 'receiver.split(":")', run: receiver => receiver.split(":") },
  { member: "receiver?.split", source: 'receiver?.split(",")', run: receiver => receiver?.split(",") },
];

export function captureNativeMethodDiagnostics() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const cases = [];
  for (const call of calls) for (const [name, factory] of factories) {
    const native = createSecondaryNativeObserver();
    const errors = createProtectedFunctionObserver();
    const events = [];
    const method = factory();
    if (method !== null && typeof method === "object") for (const key of [Symbol.toPrimitive, "toString", "valueOf", "toJSON"]) {
      Object.defineProperty(method, key, { configurable: true, get() {
        events.push({ phase: "unexpected-coercion", key: typeof key === "symbol" ? "Symbol.toPrimitive" : key });
        throw new Error("Diagnostic construction consumed a coercion getter");
      } });
    }
    const receiver = Object.defineProperty({}, "split", { get() {
      assert.equal(this, receiver);
      assert.equal(arguments.length, 0);
      events.push({ phase: "get:split" });
      return method;
    } });
    const input = native.snapshot(method);
    let caught;
    try { call.run(receiver); } catch (error) { caught = error; }
    assert.ok(caught instanceof TypeError);
    const error = errors.error(caught);
    const after = native.snapshot(method);
    assert.deepEqual(events, [{ phase: "get:split" }]);
    assert.deepEqual(after, input);
    cases.push({ name, member: call.member, source: call.source, input, error, events, after, functions: native.functions });
  }
  return { contract: "native-method-diagnostics", version: "1.7.6", runtime: { bun: Bun.version }, cases };
}

if (import.meta.main) {
  assert.equal(process.argv.length, 3, "Pass the output path");
  const serialized = `${JSON.stringify(captureNativeMethodDiagnostics(), null, 2)}\n`;
  writeFileSync(process.argv[2], serialized);
  await writeObservation(serialized);
}
