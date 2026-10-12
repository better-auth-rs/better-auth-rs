import { expect, test } from "bun:test";
import { writeObservation } from "./write-observation.mjs";
import { apiKeyCleanupScenarios, captureApiKeyCleanupFields } from "./api-key-cleanup-fields-capture.mjs";

test("API Key cleanup binds mapped Date, JSON and serial-reference predicates in order", async () => {
  const observation = await captureApiKeyCleanupFields();
  expect(observation.cases.map(captured => captured.scenario)).toStrictEqual(apiKeyCleanupScenarios);
  for (const captured of observation.cases) {
    await writeObservation(`${JSON.stringify({ contract: "api-key-cleanup-fields", version: observation.version, backend: observation.backend, current: observation.current, case: captured })}\n`);
  }
  const fixture = await Bun.file(new URL("../../../tests/fixtures/api-key-cleanup-fields-1.7.6.json", import.meta.url)).json();
  expect(observation).toStrictEqual(fixture);
});
