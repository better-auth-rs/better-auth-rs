import { expect, test } from "bun:test";
import {
  capturePluginDisplayJson, displayJsonTargets, displayJsonValues,
  displayJsonValueOperations, displayJsonProjectionModes, displayJsonFailureCases,
} from "./plugin-display-json-capture.mjs";

for (const backend of ["memory", "sqlite", "postgres", "mysql"] as const) {
  const unavailable = backend === "postgres" ? !process.env.BETTER_AUTH_TEST_POSTGRES_URL
    : backend === "mysql" ? !process.env.BETTER_AUTH_TEST_MYSQL_URL : false;
  test.skipIf(unavailable)(`${backend} JSON display fields preserve complete rows, callback phases, errors and storage`, async () => {
    const fixture = await Bun.file(new URL(`../../../tests/fixtures/plugin-display-json-${backend}-1.7.6.json`, import.meta.url)).json();
    const observed = await capturePluginDisplayJson(backend);
    expect(observed.version).toBe("1.7.6");
    expect(observed.backend).toBe(backend);
    expect(observed.models.map(({ model, field }: { model: string; field: string }) => ({ model, field }))).toStrictEqual(displayJsonTargets);
    for (const model of observed.models) {
      expect(model.cases.map((value: { name: string }) => value.name)).toStrictEqual(displayJsonValues.map(value => value.name));
      for (const value of model.cases) {
        expect(value.operations.map((operation: { name: string }) => operation.name)).toStrictEqual(displayJsonValueOperations);
      }
      expect(model.defaults.map((value: { name: string }) => value.name)).toStrictEqual(["omitted", "undefined", "null"]);
      for (const value of model.defaults) {
        expect(value.operations.map((operation: { events: { phase: string }[] }) => operation.events.map(event => event.phase)))
          .toStrictEqual([["default", "input", "output"], ["onUpdate", "input", "output"], ["output"]]);
      }
      expect(model.projections.map((value: { name: string }) => value.name)).toStrictEqual(displayJsonProjectionModes);
      expect(model.failures.map((value: { name: string }) => value.name))
        .toStrictEqual(displayJsonFailureCases.map(({ operation, phase }) => `${operation}-${phase}`));
      for (const failure of model.failures) {
        expect(failure.result.returned).toBe(false);
        expect(failure.result.error.sameCallbackError).toBe(true);
      }
    }
    expect(observed).toStrictEqual(fixture);
  }, 60_000);
}
