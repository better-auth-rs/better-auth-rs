import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { captureTelemetryFieldUnique } from "./telemetry-fields-unique-capture.mjs";

const fixture = new URL("../../../tests/fixtures/telemetry-fields-unique-1.7.6.json", import.meta.url);
const expected = JSON.parse(readFileSync(fixture, "utf8"));
assert.deepEqual(await captureTelemetryFieldUnique(), expected);
