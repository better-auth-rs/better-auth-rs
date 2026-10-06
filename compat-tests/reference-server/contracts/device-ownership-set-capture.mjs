import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { captureDeviceOwnershipCase } from "./device-ownership-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const scenarios = [
  {
    name: "scope-in-match-after-prepare",
    ownershipWhere: { field: "scope", operator: "in", value: ["prepared"] },
    matchingBackends: ["memory", "sqlite"],
  },
  {
    name: "tenant-alias-in-mismatch-after-prepare",
    ownershipWhere: { field: "stored_tenant", operator: "in", value: ["tenant-before"] },
    decoyFields: { tenantKey: "tenant-before" },
    matchingBackends: [],
  },
  {
    name: "tenant-not-in-match-after-prepare",
    ownershipWhere: { field: "tenantKey", operator: "not_in", value: ["tenant-before"] },
    matchingBackends: ["memory", "sqlite"],
  },
  {
    name: "tenant-not-in-mismatch-after-prepare",
    ownershipWhere: { field: "tenantKey", operator: "not_in", value: ["tenant-after"] },
    decoyFields: { tenantKey: "tenant-before" },
    matchingBackends: [],
  },
  {
    name: "revision-in-numbers",
    ownershipWhere: { field: "revision", operator: "in", value: [2.5, 3] },
    matchingBackends: ["memory", "sqlite"],
  },
  {
    name: "revision-in-numeric-strings",
    ownershipWhere: { field: "revision", operator: "in", value: [" 2.5 ", "3"] },
    matchingBackends: ["memory", "sqlite"],
  },
  {
    name: "revision-not-in-numeric-strings",
    ownershipWhere: { field: "revision", operator: "not_in", value: [" 2.5 ", "3"] },
    decoyFields: { revision: 4 },
    matchingBackends: [],
  },
  {
    name: "revision-in-mixed-strings",
    ownershipWhere: { field: "revision", operator: "in", value: ["2.5", "oops"] },
    matchingBackends: ["sqlite"],
  },
  {
    name: "tenant-in-empty",
    ownershipWhere: { field: "tenantKey", operator: "in", value: [] },
    matchingBackends: [],
  },
  {
    name: "tenant-not-in-empty",
    ownershipWhere: { field: "tenantKey", operator: "not_in", value: [] },
    matchingBackends: ["memory", "sqlite"],
  },
  {
    name: "tenant-null-not-in",
    ownershipWhere: { field: "tenantKey", operator: "not_in", value: ["foreign"] },
    preparedFields: { tenantKey: null },
    matchingBackends: ["memory"],
  },
];

async function captureCase(backend, mode, scenario) {
  return captureDeviceOwnershipCase(backend, mode, {
    name: scenario.name,
    ownershipWhere: scenario.ownershipWhere,
    decoy: true,
    fields: {
      tenantKey: { type: "string", fieldName: "stored_tenant", required: false },
      revision: { type: "number", fieldName: "stored_revision", required: false },
    },
    initialFields: { tenantKey: "tenant-before", revision: 1 },
    preparedFields: { tenantKey: "tenant-after", revision: 2.5, scope: "prepared", ...scenario.preparedFields },
    decoyFields: { tenantKey: "tenant-after", revision: 2.5, scope: "prepared", ...scenario.decoyFields },
    expectedClaim: scenario.matchingBackends.includes(backend) ? "requested" : null,
  });
}

export async function captureDeviceOwnershipSets() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) {
    const cases = [];
    for (const scenario of scenarios) cases.push(await captureCase(backend, "direct", scenario));
    for (const scenario of scenarios.slice(0, 2)) cases.push(await captureCase(backend, "transaction", scenario));
    backends.push({ backend, cases });
  }
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureDeviceOwnershipSets(), null, 2)}\n`);
}
