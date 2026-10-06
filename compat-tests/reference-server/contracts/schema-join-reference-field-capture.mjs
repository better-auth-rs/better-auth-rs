import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { observeSchemaJoinReferenceBoundary } from "./schema-join-reference-conflict-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const reference = (model, field) => ({ references: { model, field } });
const missingUser = "Field missingUserField not found in model user";
const missingAccount = "Field missingAccountField not found in model account";
const multiple = (model, base) => `Multiple foreign keys found for model ${model} and base model ${base} while performing join operation. Only one foreign key is supported.`;
const scenarios = [
  {
    name: "unknown-user-target",
    accountFields: { userId: reference("user", "missingUserField") },
    errors: { accounts: missingUser, owner: missingUser },
  },
  {
    name: "unknown-account-forward-target",
    userFields: { name: reference("account", "missingAccountField") },
    errors: { owner: missingAccount },
  },
  {
    name: "unknown-account-reverse-target",
    accountFields: { userId: {} },
    userFields: { image: reference("account", "missingAccountField") },
    errors: { accounts: missingAccount, owner: missingAccount },
  },
  {
    name: "multiple-before-target-field",
    accountFields: {
      userId: reference("user", "missingUserField"),
      accessToken: reference("user", "id"),
    },
    errors: { accounts: multiple("account", "user"), owner: multiple("user", "account") },
  },
  {
    name: "unknown-model-before-target-field",
    accountFields: {
      userId: reference("user", "missingUserField"),
      accessToken: reference("missingModel", "id"),
    },
    errors: { accounts: 'Model "missingModel" not found in schema', owner: 'Model "missingModel" not found in schema' },
  },
  ...["id", "_id"].map(field => ({
    name: `primary-${field}-before-alias`,
    userFields: { id: { fieldName: "stored_id" }, name: { fieldName: field } },
    accountFields: { userId: reference("user", field) },
  })),
  {
    name: "literal-user-field-alias",
    userFields: { name: { fieldName: "stored_name" } },
    accountFields: { userId: reference("user", "stored_name") },
  },
  {
    name: "logical-before-physical-field",
    userFields: { name: { fieldName: "stored_name" }, lookup: { fieldName: "name" } },
    accountFields: { userId: reference("user", "name") },
  },
  {
    name: "unregistered-plugin-user-field",
    accountFields: { userId: reference("user", "username") },
    errors: { accounts: "Field username not found in model user", owner: "Field username not found in model user" },
  },
  {
    name: "declared-additional-user-field",
    userFields: { username: {} },
    accountFields: { userId: reference("user", "username") },
  },
  {
    name: "unrelated-target-field-unvisited",
    accountFields: { accessToken: reference("session", "missingSessionField") },
  },
  {
    name: "empty-alias-native-order",
    userFields: { image: { fieldName: "" }, name: { fieldName: "" } },
    accountFields: { userId: reference("user", "") },
  },
];

async function observe(scenario, joins, operation) {
  const events = [];
  const fields = (model, configured = {}) => Object.fromEntries(Object.entries(configured).map(([name, field]) => [name, {
    type: "string", ...field,
    transform: { output: value => { events.push(["output", `${model}.${name}`, value]); return value; } },
  }]));
  const options = {
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins } },
    user: { modelName: "auth_users", additionalFields: fields("user", scenario.userFields) },
    account: { modelName: "auth_accounts", additionalFields: fields("account", scenario.accountFields) },
  };
  const result = await observeSchemaJoinReferenceBoundary(options, operation, events);
  const error = scenario.errors?.[operation];
  if (error) {
    assert.deepEqual(result, { error });
    assert.deepEqual(events, [], "Reference field failures must precede reads and output callbacks");
  } else {
    assert.equal(result, null);
    assert.equal(events.length, 1);
    assert.equal(events[0][0], "findOne");
    if (joins) {
      const key = operation === "accounts" ? "auth_accounts" : "auth_users";
      const on = events[0][1].join[key].on;
      const target = operation === "accounts" ? on.from : on.to;
      if (scenario.name.startsWith("primary-")) assert.equal(target, operation === "accounts" ? "id" : "stored_id");
      if (["literal-user-field-alias", "logical-before-physical-field"].includes(scenario.name)) assert.equal(target, "stored_name");
      if (scenario.name === "empty-alias-native-order") assert.equal(target, "name");
    }
  }
  return { ...scenario, joins, operation, events, result };
}

export async function captureSchemaJoinReferenceFields() {
  const cases = [];
  for (const scenario of scenarios) for (const joins of [false, true]) for (const operation of ["accounts", "owner"]) {
    cases.push(await observe(scenario, joins, operation));
  }
  assert.equal(cases.length, 52);
  return { version, cases };
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureSchemaJoinReferenceFields(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
