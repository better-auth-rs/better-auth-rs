import { expect, test } from "bun:test";
import { writeObservation } from "./write-observation.mjs";
import { captureCoreQueryIdSort, coreQueryIdSortOperations } from "./core-query-id-sort-capture.mjs";

test("Memory User sorting resolves ID aliases after Where binding and before output", async () => {
  const observation = await captureCoreQueryIdSort();
  expect(observation.cases.map(captured => [captured.operation, captured.serial])).toStrictEqual(
    coreQueryIdSortOperations.flatMap(operation => [false, true].map(serial => [operation, serial])),
  );
  for (const captured of observation.cases) {
    expect(captured.setup).toHaveLength(2);
    expect(captured.steps).toHaveLength(2);
    for (const step of captured.steps) {
      expect(step.result.users).toHaveLength(2);
      expect(step.result.total).toBe(2);
      expect(step.result.users.map(user => user.id)).toStrictEqual(
        captured.operation === "sort-only" && step.attempt === 1 ? ["2", "1"] : ["1", "2"],
      );
    }
    await writeObservation(`${JSON.stringify({ contract: "core-query-id-sort", version: observation.version, backend: observation.backend, case: captured })}\n`);
  }
  const fixture = await Bun.file(new URL("../../../tests/fixtures/core-query-id-sort-1.7.6.json", import.meta.url)).json();
  expect(observation).toStrictEqual(fixture);
});
