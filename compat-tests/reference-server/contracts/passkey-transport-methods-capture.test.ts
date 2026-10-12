import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { passkeyTransportCases } from "./passkey-transport-methods-capture.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { readStandaloneFixture, runStandaloneCapture } from "./standalone-capture";
import { writeObservation } from "./write-observation.mjs";

test("Passkey split authentication preserves complete native results, errors and persisted records", async () => {
  const fixture = new URL("../../../tests/fixtures/passkey-transport-methods-1.7.6.json", import.meta.url);
  const expected = JSON.parse(readStandaloneFixture(fixture));
  expect(expected.contract).toBe("passkey-transport-methods");
  expect(expected.version).toBe("1.7.6");
  expect(expected.backend).toBe("memory");
  expect(expected.cases.map(({ scenario }: { scenario: unknown }) => scenario)).toStrictEqual(passkeyTransportCases);
  const result = await runStandaloneCapture(new URL("./passkey-transport-methods-capture.mjs", import.meta.url));
  await writeObservation(result.stdout);
  expect({ status: result.status, stderr: result.stderr }, `Replay evidence: ${result.directory}`).toEqual({ status: 0, stderr: "" });
  const actual = JSON.parse(readFileSync(result.output, "utf8"));
  expect(Object.keys(actual)).toStrictEqual(Object.keys(expected));
  for (const key of ["contract", "version", "backend", "provenance", "boundary"]) {
    assertObservationReplay(actual[key], expected[key], `passkey-transport-methods/${key}`);
  }
  expect(actual.cases).toHaveLength(expected.cases.length);
  for (const [index, entry] of expected.cases.entries()) {
    expect(Object.keys(actual.cases[index])).toStrictEqual(Object.keys(entry));
    for (const key of ["name", "scenario", "input", "runtime"]) {
      assertObservationReplay(actual.cases[index][key], entry[key], `passkey-transport-methods/${entry.name}/${key}`);
    }
  }
}, 120_000);
