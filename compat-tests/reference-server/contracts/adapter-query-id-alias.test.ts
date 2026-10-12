import { expect, test } from "bun:test";
import { writeObservation } from "./write-observation.mjs";
import { captureAdapterQueryIdAliases } from "./adapter-id-slot-capture.mjs";

test("Memory shared plugin CRUD retains first-query ID aliases across JWK and Wallet", async () => {
  const observation = await captureAdapterQueryIdAliases();
  expect(observation.cases.map(captured => [captured.model, captured.serial, captured.operation])).toStrictEqual(
    ["jwks", "walletAddress"].flatMap(model => [false, true].flatMap(serial => ["findOne", "update", "delete"].map(operation => [model, serial, operation]))),
  );
  for (const captured of observation.cases) {
    await writeObservation(`${JSON.stringify({ contract: "adapter-query-id-alias", version: observation.version, backend: observation.backend, case: captured })}\n`);
  }
  const fixture = await Bun.file(new URL("../../../tests/fixtures/adapter-query-id-alias-1.7.6.json", import.meta.url)).json();
  expect(observation).toStrictEqual(fixture);
});
