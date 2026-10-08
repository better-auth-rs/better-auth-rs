import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { captureDeviceGrant } from "./device-grant-capture.mjs";
import { captureDeviceGrantFailures } from "./device-grant-failures.mjs";
import { captureDeviceRedemptionBackend } from "./device-redemption.ts";

export async function captureDeviceGrantSql(backend, { diagnostics = [] } = {}) {
  assert.ok(["sqlite", "postgres", "mysql"].includes(backend));
  const grant = await captureDeviceGrant(backend);
  diagnostics.push({ backend, grant });
  const redemption = await captureDeviceRedemptionBackend(backend);
  diagnostics.push({ backend, redemption });
  const failures = await captureDeviceGrantFailures(backend, diagnostics);
  assert.equal(grant.version, "1.7.6");
  assert.equal(grant.cases.length, 4);
  assert.equal(redemption.cases.length, 3);
  assert.equal(failures.length, 6);
  return { version: grant.version, backend, grant, redemption, failures };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a SQL backend and Device grant fixture output path");
  const diagnostics = [];
  try {
    const observed = await captureDeviceGrantSql(backend, { diagnostics });
    writeFileSync(`${output}.raw.json`, `${JSON.stringify(observed, null, 2)}\n`);
    writeFileSync(output, `${JSON.stringify(observed, null, 2)}\n`);
  } finally {
    writeFileSync(`${output}.raw-diagnostics.json`, `${JSON.stringify(diagnostics, null, 2)}\n`);
  }
}
