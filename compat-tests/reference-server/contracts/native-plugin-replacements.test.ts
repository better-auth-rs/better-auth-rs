import { expect, test } from "bun:test";
import {
  captureNativePluginReplacements, nativeReplacementTargets, nativeReplacementInputs,
  nativeReplacementOperations, nativeReplacementProjections, nativeReplacementFailures,
} from "./native-plugin-replacements-capture.mjs";

for (const backend of ["memory", "sqlite"] as const) {
  test(`${backend} native plugin replacements preserve complete declarations, callbacks, rows and storage`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/native-plugin-replacements-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await captureNativePluginReplacements(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.backend).toBe(backend);
    expect(observed.targets.map(({ name, model, field, type }: { name: string; model: string; field: string; type: string }) => ({ name, model, field, type })))
      .toStrictEqual(nativeReplacementTargets);
    for (const target of observed.targets) {
      expect(target.declaration.replacement.type).toBe(target.type);
      expect(target.declaration.replacement.fieldName).toBe(target.column);
      expect(target.declaration.replacement.required).toBe(false);
      expect(target.declaration.replacement).not.toHaveProperty("defaultValue");
      expect(target.declaration.replacement).not.toHaveProperty("references");
      expect(target.cases.map(({ name }: { name: string }) => name)).toStrictEqual(nativeReplacementInputs);
      for (const scenario of target.cases) {
        expect(scenario.operations.map(({ name }: { name: string }) => name)).toStrictEqual(nativeReplacementOperations);
        expect(scenario.operations.every(({ returned }: { returned: boolean }) => returned)).toBe(true);
      }
      expect(target.defaults.map(({ name }: { name: string }) => name)).toStrictEqual(["create-default", "update-default", "read-default"]);
      expect(target.projections.map(({ name }: { name: string }) => name)).toStrictEqual(nativeReplacementProjections);
      expect(target.failures.map(({ name }: { name: string }) => name))
        .toStrictEqual(nativeReplacementFailures.map(({ operation, phase }) => `${operation}-${phase}`));
      for (const failure of target.failures) {
        expect(failure.result.returned).toBe(false);
        expect(failure.result.error.sameCallbackError).toBe(true);
      }
      if (backend === "sqlite") {
        expect(target.catalog.catalog.columns.some(({ name }: { name: string }) => name === target.column)).toBe(true);
        expect(target.catalog.catalog.columns.some(({ name }: { name: string }) => name === target.field)).toBe(false);
      }
      if (target.name === "wallet-owner-number") {
        expect(target.declaration.original.references).toStrictEqual({ model: "user", field: "id" });
        if (backend === "sqlite") expect(target.catalog.catalog.foreignKeys).toStrictEqual([]);
      }
    }
    expect(observed).toStrictEqual(fixture);
  }, 60_000);
}
