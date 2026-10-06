import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createAdapterFactory } from "@better-auth/core/db/adapter";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const scenarios = [
  ...["account", "session", "verification"].map(userTable => ({
    name: `user-alias-${userTable}`, userTable, accountReference: userTable, invalid: true,
  })),
  { name: "literal-user-alias", userTable: "app_users", accountReference: "app_users", invalid: false },
  { name: "inactive-plugin-alias", userTable: "passkey", accountReference: "passkey", invalid: false },
  { name: "logical-user-reference", userTable: "account", accountReference: "user", invalid: false },
  ...["user", "session", "verification"].map(accountTable => ({
    name: `account-alias-${accountTable}`, accountTable, userReferences: true, invalid: false,
  })),
  ...["session", "verification"].flatMap(userTable => [false, true].map(storeCore => ({
    name: `${userTable}-${storeCore ? "database" : "secondary"}`, userTable,
    accountReference: userTable, secondaryStorage: true, storeCore, invalid: storeCore,
  }))),
];

export async function observeSchemaJoinReferenceBoundary(options, operation, events) {
  // The real adapter factory validates references before invoking the raw reader.
  const adapter = createAdapterFactory({
    config: { adapterId: "schema-reference-boundary", supportsJSON: true },
    adapter: () => ({
      async findOne(input) { events.push(["findOne", input]); return null; },
    }),
  })(options);
  try {
    return operation === "accounts"
      ? await adapter.findOne({ model: "user", where: [{ field: "id", value: "owner" }], join: { account: true } })
      : await adapter.findOne({ model: "account", where: [{ field: "id", value: "account" }], join: { user: true } });
  } catch (error) {
    return { error: error.message };
  }
}

async function observe(scenario, joins, operation) {
  const events = [];
  const output = field => value => { events.push(["output", field, value]); return value; };
  const userTable = scenario.userTable ?? "auth_users";
  const accountTable = scenario.accountTable ?? "auth_accounts";
  const userFields = { name: { type: "string", transform: { output: output("user.name") } } };
  if (scenario.userReferences) {
    userFields.name.references = { model: accountTable, field: "id" };
    userFields.image = { type: "string", required: false, references: { model: accountTable, field: "id" } };
  }
  const accountFields = {
    accountId: { type: "string", transform: { output: output("account.accountId") } },
    userId: { type: "string", references: { model: scenario.accountReference ?? "user", field: "id" } },
  };
  const options = {
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins } },
    user: { modelName: userTable, additionalFields: userFields },
    account: { modelName: accountTable, additionalFields: accountFields },
    session: { modelName: "auth_sessions", storeSessionInDatabase: scenario.storeCore ?? false },
    verification: { modelName: "auth_verifications", storeInDatabase: scenario.storeCore ?? false },
    ...(scenario.secondaryStorage ? { secondaryStorage: {
      async get() { return null; }, async set() {}, async delete() {},
    } } : {}),
  };
  const result = await observeSchemaJoinReferenceBoundary(options, operation, events);
  if (scenario.invalid) {
    const [model, base] = operation === "accounts" ? ["account", "user"] : ["user", "account"];
    assert.deepEqual(result, { error: `No foreign key found for model ${model} and base model ${base} while performing join operation.` });
    assert.deepEqual(events, [], "Reference failures must precede reads and output callbacks");
  } else {
    assert.equal(result, null);
    assert.equal(events.length, 1);
    assert.equal(events[0][0], "findOne");
  }
  return { ...scenario, userTable, accountTable, joins, operation, events, result };
}

export async function captureSchemaJoinReferenceConflicts() {
  const cases = [];
  for (const scenario of scenarios) for (const joins of [false, true]) for (const operation of ["accounts", "owner"]) {
    cases.push(await observe(scenario, joins, operation));
  }
  return { version, cases };
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureSchemaJoinReferenceConflicts(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
