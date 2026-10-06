import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { observeSchemaJoinReferenceBoundary } from "./schema-join-reference-conflict-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const scenarios = [
  {
    name: "unknown-owner-reference",
    accountReferences: [["userId", "missingOwner"]],
    unknownModel: "missingOwner",
  },
  {
    name: "unknown-after-valid-reference",
    accountReferences: [["accessToken", "missingAfterValid"]],
    unknownModel: "missingAfterValid",
  },
  {
    name: "unknown-after-duplicate-references",
    accountReferences: [["accessToken", "user"], ["refreshToken", "missingAfterDuplicate"]],
    unknownModel: "missingAfterDuplicate",
  },
  {
    name: "unvisited-reverse-reference",
    userReferences: [["image", "missingUser"]],
    unknownModel: "missingUser",
    errorOperation: "owner",
  },
  {
    name: "unknown-order-first",
    accountReferences: [["firstReference", "firstMissing"], ["secondReference", "secondMissing"]],
    unknownModel: "firstMissing",
  },
  {
    name: "unknown-order-reversed",
    accountReferences: [["secondReference", "secondMissing"], ["firstReference", "firstMissing"]],
    unknownModel: "secondMissing",
  },
  {
    name: "active-session-alias",
    accountReferences: [["accessToken", "auth_sessions"]],
  },
  {
    name: "inactive-session-alias",
    accountReferences: [["accessToken", "auth_sessions"]],
    secondaryStorage: true,
    unknownModel: "auth_sessions",
  },
];

async function observe(scenario, joins, operation) {
  const events = [];
  const output = field => value => { events.push(["output", field, value]); return value; };
  const fields = (model, references, first) => {
    const fields = { [first]: { type: "string", transform: { output: output(`${model}.${first}`) } } };
    for (const [name, reference] of references ?? []) fields[name] = {
      type: "string", references: { model: reference, field: "id" },
      transform: { output: output(`${model}.${name}`) },
    };
    return fields;
  };
  const options = {
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins } },
    user: { modelName: "auth_users", additionalFields: fields("user", scenario.userReferences, "name") },
    account: { modelName: "auth_accounts", additionalFields: fields("account", scenario.accountReferences, "accountId") },
    session: { modelName: "auth_sessions", storeSessionInDatabase: false },
    verification: { modelName: "auth_verifications", storeInDatabase: false },
    ...(scenario.secondaryStorage ? { secondaryStorage: {
      async get() { return null; }, async set() {}, async delete() {},
    } } : {}),
  };
  const result = await observeSchemaJoinReferenceBoundary(options, operation, events);
  const invalid = scenario.unknownModel && (!scenario.errorOperation || scenario.errorOperation === operation);
  if (invalid) {
    assert.deepEqual(result, { error: `Model "${scenario.unknownModel}" not found in schema` });
    assert.deepEqual(events, [], "Unknown model errors must precede reads and output callbacks");
  } else {
    assert.equal(result, null);
    assert.equal(events.length, 1);
    assert.equal(events[0][0], "findOne");
  }
  return { ...scenario, joins, operation, events, result };
}

export async function captureSchemaJoinReferenceUnknowns() {
  const cases = [];
  for (const scenario of scenarios) for (const joins of [false, true]) for (const operation of ["accounts", "owner"]) {
    cases.push(await observe(scenario, joins, operation));
  }
  assert.equal(cases.length, 32);
  return { version, cases };
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureSchemaJoinReferenceUnknowns(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
