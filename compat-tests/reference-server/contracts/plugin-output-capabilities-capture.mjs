import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { deviceAuthorization, jwt, twoFactor } from "better-auth/plugins";
import { address, base, walletPlugin } from "./wallet-additional-fields.ts";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");
const createdAt = "2030-01-02T03:04:05.123Z";
const initialDate = "2029-01-02T03:04:05.000Z";
const json = value => JSON.parse(JSON.stringify(value));
const callbackValue = value => value === undefined ? { type: "undefined" } : json(value);
export const modelNames = ["apikey", "passkey", "deviceCode", "twoFactor", "jwks", "walletAddress"];
export const observationNames = ["create", "read-rewrite", "read-error"];
const policies = () => ({
  enabledFlag: { type: "boolean", fieldName: "stored_enabled_flag", required: false },
  disabledFlag: { type: "boolean", fieldName: "stored_disabled_flag", required: false },
  labels: { type: "string[]", fieldName: "stored_labels", required: false },
  scores: { type: "number[]", fieldName: "stored_scores", required: false },
  shortDate: { type: "date", fieldName: "stored_short_date", required: false },
  invalidDate: { type: "date", fieldName: "stored_invalid_date", required: false },
});
const additionalInput = () => ({
  enabledFlag: true, disabledFlag: false, labels: ["first", "second"], scores: [1, 2.5],
  shortDate: new Date(initialDate), invalidDate: new Date(initialDate),
});
const replacements = {
  enabledFlag: 0, disabledFlag: 1, labels: '["changed","third"]', scores: "[4,5.5]",
  shortDate: "2030-02-03", invalidDate: "not-a-date",
};

const nativeInputs = userId => ({
  apikey: {
    name: "Desk", start: null, prefix: null, key: "ordinary-stored-hash", referenceId: userId,
    configId: "default", refillInterval: 60000, refillAmount: 10, lastRefillAt: null, enabled: true,
    rateLimitEnabled: true, rateLimitTimeWindow: 60000, rateLimitMax: 3, requestCount: 0, remaining: 10,
    lastRequest: null, expiresAt: null, createdAt: new Date(createdAt), updatedAt: new Date(createdAt),
    permissions: null, metadata: null,
  },
  passkey: {
    name: "Desk", userId, credentialID: "ordinary-credential", publicKey: "ordinary-public-key",
    counter: 0, deviceType: "singleDevice", backedUp: false, transports: null,
    createdAt: new Date(createdAt), aaguid: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
  },
  deviceCode: {
    deviceCode: "ordinary-device", userCode: "ordinary-user", userId,
    expiresAt: new Date("2032-01-02T03:04:05.000Z"), status: "pending", lastPolledAt: null,
    pollingInterval: 5000, clientId: "ordinary-client", scope: "read",
  },
  twoFactor: {
    userId, secret: "ordinary-encrypted-secret", backupCodes: "ordinary-encrypted-codes",
    verified: false, failedVerificationCount: 0, lockedUntil: null,
  },
  jwks: {
    publicKey: "public", privateKey: "private", createdAt: new Date(createdAt),
    expiresAt: null, alg: "EdDSA", crv: null,
  },
  walletAddress: { userId, address, chainId: 1, isPrimary: false, createdAt: new Date(createdAt) },
});

async function captureBackend(backend) {
  const memory = Object.fromEntries(["user", "session", "account", "verification", ...modelNames].map(model => [model, []]));
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = fields => ({
    ...base, database: sqlite ?? memoryAdapter(memory),
    plugins: [apiKey(), passkey(), deviceAuthorization(), twoFactor(), jwt(), walletPlugin(), {
      id: "ordinary-plugin-output-capabilities",
      schema: Object.fromEntries(modelNames.map(model => [model, { fields }])),
    }],
  });
  try {
    if (sqlite) await (await getMigrations(options(policies()))).runMigrations();
    const reader = (await betterAuth(options(policies())).$context).adapter;
    const owner = await reader.create({ model: "user", data: {
      name: "Plugin output owner", email: "output@wallet-fields.test", emailVerified: false,
      createdAt: new Date(createdAt), updatedAt: new Date(createdAt),
    } });
    const events = [];
    const outputError = new Error("ordinary plugin output error");
    let operation;
    // Preserve JavaScript Date identity separately because JSON cannot distinguish dates from strings.
    let referenceDateKinds;
    const recordDateKind = (phase, field, value) => {
      if (field !== "shortDate" && field !== "invalidDate") return;
      const kind = value instanceof Date ? Number.isNaN(value.getTime()) ? "invalid-date" : "date" : typeof value;
      referenceDateKinds.push({ operation, phase, field, kind });
    };
    const fields = Object.fromEntries(Object.entries(policies()).map(([field, policy]) => [field, {
      ...policy,
      transform: {
        input(value) {
          events.push(["input", field, callbackValue(value)]);
          recordDateKind("input", field, value);
          return value;
        },
        output(value) {
          events.push(["output", field, callbackValue(value)]);
          recordDateKind("output", field, value);
          if (operation === "read-error" && field === "labels") throw outputError;
          return operation === "create" ? value : replacements[field];
        },
      },
    }]));
    const adapter = (await betterAuth(options(fields)).$context).adapter;
    const models = [];
    for (const [model, native] of Object.entries(nativeInputs(owner.id))) {
      referenceDateKinds = [];
      let identity;
      const visible = (row, phase) => {
        assert.notEqual(row, null);
        assert.deepEqual(Object.keys(row).sort(), ["id", ...Object.keys(native), ...Object.keys(policies())].sort());
        assert.equal(typeof row.id, "string");
        assert.ok(row.id.length > 0);
        if (identity === undefined) identity = row.id;
        assert.equal(row.id, identity);
        for (const [field, value] of Object.entries(native)) {
          if (value instanceof Date) {
            assert.ok(row[field] instanceof Date);
            assert.equal(row[field].toISOString(), value.toISOString());
          } else assert.deepEqual(row[field], value);
        }
        for (const field of ["shortDate", "invalidDate"]) recordDateKind(phase, field, row[field]);
        return json({
          ...row, id: "<model-id>",
          ...("userId" in native ? { userId: "<owner-id>" } : {}),
          ...("referenceId" in native ? { referenceId: "<owner-id>" } : {}),
          ...("createdAt" in native ? { createdAt: "<created-at>" } : {}),
          ...("updatedAt" in native ? { updatedAt: "<created-at>" } : {}),
        });
      };
      const where = () => {
        if (model === "deviceCode") return [{ field: "deviceCode", value: native.deviceCode }];
        if (model === "twoFactor") return [{ field: "userId", value: owner.id }];
        if (model === "walletAddress") return [{ field: "address", value: address }, { field: "chainId", value: 1 }];
        return [{ field: "id", value: identity }];
      };
      const observations = [];
      for (operation of observationNames) {
        assert.equal(events.length, 0);
        let result;
        if (operation === "read-error") {
          let sameError = false;
          try { await adapter.findOne({ model, where: where() }); }
          catch (error) {
            if (error !== outputError) throw error;
            sameError = true;
          }
          assert.equal(sameError, true, "The configured output callback must reject the read");
          result = { sameError, message: outputError.message };
        } else {
          const row = operation === "create"
            ? await adapter.create({ model, data: { ...native, ...additionalInput() } })
            : await adapter.findOne({ model, where: where() });
          result = visible(row, "result");
        }
        const expectedPhases = operation === "create" ? ["input", "output"] : ["output"];
        const expectedFields = operation === "read-error" ? Object.keys(policies()).slice(0, 3) : Object.keys(policies());
        assert.deepEqual(events.map(([phase, field]) => [phase, field]), expectedPhases.flatMap(phase => expectedFields.map(field => [phase, field])));
        const observation = {
          name: operation, events: events.splice(0), result,
          stored: visible(await reader.findOne({ model, where: where() }), "stored"),
        };
        if (operation !== "create") assert.deepEqual(observation.stored, observations[0].stored);
        observations.push(observation);
      }
      models.push({ model, observations, referenceDateKinds });
    }
    return { backend, models };
  } finally {
    sqlite?.close();
  }
}

export async function capturePluginOutputCapabilities() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) backends.push(await captureBackend(backend));
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await capturePluginOutputCapabilities(), null, 2)}\n`);
}
