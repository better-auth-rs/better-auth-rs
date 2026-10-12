import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureNativePropertyClone } from "./native-property-clone-capture.mjs";

export const arrayBoundaryCases = ["hidden-static", "fill-hole", "grow", "shrink"]
  .map(mode => ({ kind: "array", mode }));

export async function captureNativePropertyCloneArrayBoundaries() {
  return captureNativePropertyClone(arrayBoundaryCases);
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass the native property clone array output path");
  writeFileSync(process.argv[2], `${JSON.stringify(await captureNativePropertyCloneArrayBoundaries(), null, 2)}\n`);
}
