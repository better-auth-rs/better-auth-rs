import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { getCurrentAdapter, runWithTransaction } from "@better-auth/core/context";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { deviceAuthorization, redeemDeviceCode } from "better-auth/plugins/device-authorization";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const json = value => JSON.parse(JSON.stringify(value));
const ownerTime = "2030-01-01T00:00:00.000Z";
const expiresAt = "2100-01-01T00:00:00.000Z";
const authorizationContext = { issuer: "ordinary-issuer" };
const redemptionContext = { issuedFor: "ordinary-issuer" };
const deviceFields = [
  "id", "deviceCode", "userCode", "userId", "expiresAt", "status",
  "lastPolledAt", "pollingInterval", "clientId", "scope", "tenantKey",
];
const userFields = ["id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt"];
const scenarios = [
  { name: "tenant-match-after-prepare", ownershipWhere: { field: "tenantKey", value: "tenant-after" } },
  { name: "tenant-mismatch-after-prepare", ownershipWhere: { field: "tenantKey", value: "tenant-before" } },
  { name: "or-tenant-mismatch", ownershipWhere: { field: "tenantKey", value: "foreign-tenant", connector: "OR" } },
];

async function captureCase(backend, mode, { name, ownershipWhere, decoy = false }) {
  const memory = { user: [], session: [], account: [], verification: [], deviceCode: [] };
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  try {
    const options = {
      database: sqlite ?? memoryAdapter(memory),
      baseURL: "http://device-ownership.test",
      secret: "ordinary-device-ownership-contract-at-least-32-characters",
      logger: { disabled: true },
      telemetry: { enabled: false },
      plugins: [deviceAuthorization(), {
        id: "ordinary-device-ownership",
        schema: { deviceCode: { fields: {
          tenantKey: { type: "string", fieldName: "stored_tenant", required: false },
        } } },
      }],
    };
    if (sqlite) await (await getMigrations(options)).runMigrations();
    const context = await betterAuth(options).$context;
    const { adapter } = context;
    const owner = await adapter.create({ model: "user", data: {
      name: "Device ownership owner", email: "owner@device-ownership.test", emailVerified: false,
      image: null, createdAt: new Date(ownerTime), updatedAt: new Date(ownerTime),
    } });
    let decoyOwner;
    let decoyCode;
    if (decoy) {
      decoyOwner = await adapter.create({ model: "user", data: {
        name: "Decoy ownership owner", email: "decoy@device-ownership.test", emailVerified: false,
        image: null, createdAt: new Date(ownerTime), updatedAt: new Date(ownerTime),
      } });
      decoyCode = await adapter.create({ model: "deviceCode", data: {
        deviceCode: "decoy-device", userCode: "decoy-user", userId: decoyOwner.id,
        expiresAt: new Date(expiresAt), status: "approved", lastPolledAt: null,
        pollingInterval: 5000, clientId: "decoy-client", scope: "decoy-scope", tenantKey: "decoy-tenant",
      } });
    }
    const seeded = await adapter.create({ model: "deviceCode", data: {
      deviceCode: "ordinary-device", userCode: "ordinary-user", userId: owner.id,
      expiresAt: new Date(expiresAt), status: "approved", lastPolledAt: null,
      pollingInterval: 5000, clientId: "ordinary-client", scope: "initial", tenantKey: "tenant-before",
    } });
    assert.equal(typeof owner.id, "string");
    assert.equal(typeof seeded.id, "string");
    assert.ok(owner.id.length > 0);
    assert.ok(seeded.id.length > 0);
    if (decoy) {
      assert.equal(typeof decoyOwner.id, "string");
      assert.equal(typeof decoyCode.id, "string");
      assert.ok(decoyOwner.id.length > 0);
      assert.ok(decoyCode.id.length > 0);
      assert.notEqual(decoyOwner.id, owner.id);
      assert.notEqual(decoyCode.id, seeded.id);
    }
    const startedAt = Date.now();
    const visibleDevice = row => {
      if (row === null) return null;
      assert.deepEqual(Object.keys(row).sort(), [...deviceFields].sort());
      const isDecoy = decoy && row.id === decoyCode.id;
      assert.equal(row.id, isDecoy ? decoyCode.id : seeded.id);
      assert.equal(row.userId, isDecoy ? decoyOwner.id : owner.id);
      assert.ok(row.expiresAt instanceof Date);
      assert.equal(row.expiresAt.toISOString(), expiresAt);
      if (row.lastPolledAt !== null) {
        assert.ok(row.lastPolledAt instanceof Date);
        assert.ok(row.lastPolledAt.getTime() >= startedAt);
        assert.ok(row.lastPolledAt.getTime() <= Date.now());
      }
      return json({
        ...row, id: isDecoy ? "<decoy-device-id>" : "<device-id>",
        userId: isDecoy ? "<decoy-owner-id>" : "<owner-id>",
        lastPolledAt: row.lastPolledAt === null ? null : "<polled-at>",
      });
    };
    const visibleUser = row => {
      assert.deepEqual(Object.keys(row).sort(), [...userFields].sort());
      assert.equal(row.id, owner.id);
      return json({ ...row, id: "<owner-id>" });
    };
    const remainingRows = async active => (await active.findMany({
      model: "deviceCode", sortBy: { field: "deviceCode", direction: "asc" },
    })).map(visibleDevice);
    const before = visibleDevice(seeded);
    const beforeRows = decoy ? [visibleDevice(decoyCode), before] : [before];
    const events = [];
    let insideRemaining;
    let result = null;
    let error = null;
    const execute = async () => {
      const active = await getCurrentAdapter(adapter);
      const traced = {
        ...active,
        async consumeOne(input) {
          assert.deepEqual(input, { model: "deviceCode", where: [
            { field: "id", value: seeded.id }, ownershipWhere, { field: "status", value: "approved" },
          ] });
          events.push({ type: "consumeOne", input: json({ ...input, where: [
            { ...input.where[0], value: "<device-id>" }, ...input.where.slice(1),
          ] }) });
          const consumed = await active.consumeOne(input);
          events.push({ type: "consumeOneResult", row: visibleDevice(consumed) });
          return consumed;
        },
      };
      try {
        const redeemed = await redeemDeviceCode({
          ctx: { context: { ...context, adapter: traced } },
          deviceCode: seeded.deviceCode,
          async authorizeRedemption(row) {
            events.push({ type: "authorize", row: visibleDevice(row) });
            return { ownershipWhere, context: authorizationContext };
          },
          async prepareRedemption(row, authorization) {
            events.push({ type: "prepare", row: visibleDevice(row), authorizationContext: json(authorization) });
            const prepared = await active.update({
              model: "deviceCode", where: [{ field: "id", value: row.id }],
              update: { tenantKey: "tenant-after", scope: "prepared" },
            });
            events.push({ type: "prepared", row: visibleDevice(prepared) });
            return { issuedFor: authorization.issuer };
          },
        });
        assert.deepEqual(Object.keys(redeemed).sort(), ["claimedDeviceCode", "authorizationContext", "redemptionContext", "user"].sort());
        return json({
          ...redeemed, claimedDeviceCode: visibleDevice(redeemed.claimedDeviceCode), user: visibleUser(redeemed.user),
        });
      } finally {
        insideRemaining = await remainingRows(active);
      }
    };
    try {
      result = mode === "transaction" ? await runWithTransaction(adapter, execute) : await execute();
    } catch (caught) {
      if (!(caught instanceof APIError) || caught.body?.error !== "invalid_grant") throw caught;
      error = { status: caught.status, statusCode: caught.statusCode, body: json(caught.body) };
    }
    const remaining = await remainingRows(adapter);
    const prepared = { ...before, tenantKey: "tenant-after", scope: "prepared", lastPolledAt: "<polled-at>" };
    assert.deepEqual(events.map(event => event.type), ["authorize", "prepare", "prepared", "consumeOne", "consumeOneResult"]);
    assert.deepEqual(events[0].row, before);
    assert.deepEqual(events[1].row, before);
    assert.deepEqual(events[1].authorizationContext, authorizationContext);
    assert.deepEqual(events[2].row, prepared);
    const succeeds = name === "tenant-match-after-prepare" || (ownershipWhere.connector === "OR" && backend === "memory");
    if (succeeds) {
      const claimed = decoy ? visibleDevice(decoyCode) : prepared;
      assert.equal(error, null);
      assert.deepEqual(events[4].row, claimed);
      assert.deepEqual(result, { claimedDeviceCode: claimed, authorizationContext, redemptionContext, user: visibleUser(owner) });
      assert.deepEqual(insideRemaining, decoy ? [prepared] : []);
      assert.deepEqual(remaining, decoy ? [prepared] : []);
    } else {
      assert.equal(result, null);
      assert.equal(events[4].row, null);
      assert.deepEqual(error, {
        status: "BAD_REQUEST", statusCode: 400,
        body: { error: "invalid_grant", error_description: "Invalid device code" },
      });
      const preparedRows = decoy ? [visibleDevice(decoyCode), prepared] : [prepared];
      assert.deepEqual(insideRemaining, preparedRows);
      assert.deepEqual(remaining, mode === "transaction" ? beforeRows : preparedRows);
    }
    return { name, mode, ownershipWhere, before, ...(decoy ? { beforeRows } : {}), events, result, error, insideRemaining, remaining };
  } finally {
    sqlite?.close();
  }
}

export async function captureDeviceOwnership() {
  const backends = [];
  for (const backend of ["memory", "sqlite"]) {
    const cases = [];
    for (const scenario of scenarios) {
      for (const mode of ["direct", "transaction"]) cases.push(await captureCase(backend, mode, scenario));
    }
    cases.push(await captureCase(backend, "direct", {
      name: "or-selects-earlier-owner", decoy: true,
      ownershipWhere: { field: "tenantKey", value: "decoy-tenant", connector: "OR" },
    }));
    backends.push({ backend, cases });
  }
  return { version, backends };
}

if (import.meta.main) {
  const [output] = process.argv.slice(2);
  assert.ok(output, "Pass the fixture output path as the first argument");
  writeFileSync(output, `${JSON.stringify(await captureDeviceOwnership(), null, 2)}\n`);
}
