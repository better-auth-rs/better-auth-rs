import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeVersion } from "./secondary-native-shared.mjs";

export const nativePropertyCloneCases = ["object", "array"].flatMap(kind =>
  ["delete-inherited", "hide-later", "show-hidden", "throw-original"].map(mode => ({ kind, mode })));

async function captureCase({ kind, mode }) {
  const native = createSecondaryNativeObserver();
  const root = kind === "array" ? new Array(3) : {};
  const [first, later, tail] = kind === "array" ? ["0", "1", "2"] : ["first", "later", "tail"];
  const inherited = Object.create(Object.getPrototypeOf(root));
  Object.setPrototypeOf(root, inherited);
  const child = {};
  const original = { failure: `${kind}-${mode}`, ownUndefined: undefined };
  function getter(target, key, read, enumerable = true) {
    Object.defineProperty(target, key, { enumerable, configurable: true, get() {
      native.record(`get:${target === root ? "root" : "child"}:${key}`, { sameReceiver: this === target });
      return read();
    } });
  }
  getter(root, first, () => child);
  if (mode !== "fill-hole") {
    getter(root, later, () => "later-value", mode !== "show-hidden" && mode !== "hidden-static");
  }
  getter(root, tail, () => "tail-value");
  getter(child, "mutate", () => {
    root.mutation = "retained";
    if (mode === "delete-inherited") {
      assert.equal(Reflect.deleteProperty(root, later), true);
      Object.defineProperty(inherited, later, { enumerable: true, configurable: true, get() {
        native.record(`get:inherited:${later}`, { sameReceiver: this === root });
        return "inherited-value";
      } });
    } else if (mode === "hide-later" || mode === "show-hidden") {
      Object.defineProperty(root, later, { enumerable: mode === "show-hidden" });
    } else if (mode === "fill-hole") {
      getter(root, later, () => "inserted-value");
    } else if (mode === "grow") {
      getter(root, "3", () => "grown-value");
    } else if (mode === "shrink") {
      root.length = 1;
    } else if (mode === "hidden-static") {
      assert.equal(Object.getOwnPropertyDescriptor(root, later).enumerable, false);
    } else {
      assert.equal(mode, "throw-original");
      throw original;
    }
    return "child-value";
  });
  const before = native.snapshot({ root, inherited, original });
  let copy;
  const outcome = await native.outcome(() => { copy = structuredClone(root); return copy; }, original);
  const after = native.snapshot({ root, inherited, original });
  assert.equal(root.mutation, "retained");
  assert.equal(outcome.returned, mode !== "throw-original");
  if (mode === "throw-original") assert.equal(outcome.sameOriginal, true);
  else assert.notEqual(copy, root);
  return { name: `${kind}-${mode}`, kind, mode, before, outcome, after,
    events: native.events, functions: native.functions };
}

export async function captureNativePropertyClone(scenarios = nativePropertyCloneCases) {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const cases = [];
  for (const scenario of scenarios) cases.push(await captureCase(scenario));
  return { version: secondaryNativeVersion, runtime: { bun: Bun.version },
    boundary: "Bun structuredClone property selection after nested getters mutate later descriptors; complete descriptor graphs retain function reflection.",
    cases };
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass the native property clone output path");
  writeFileSync(process.argv[2], `${JSON.stringify(await captureNativePropertyClone(), null, 2)}\n`);
}
