import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { observeValue } from "./device-where-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

const createdAt = new Date("2030-01-02T03:04:05.000Z");
const expiresAt = new Date("2100-01-02T03:04:05.000Z");
const changedAt = new Date("2031-01-02T03:04:05.000Z");
const changedExpiry = new Date("2101-01-02T03:04:05.000Z");
const declarations = [
  { label: "Desk", token: "live-session-desk", id: "00101" },
  { label: "Travel", token: "live-session-travel", id: "00102" },
];
const scenarios = ["create", "get-native-join", "list", "update"];

function data(row, userId) {
  return {
    userId, token: row.token, expiresAt, createdAt, updatedAt: createdAt,
    ipAddress: "", userAgent: "", label: row.label, tail: `before:${row.label}`,
  };
}

async function captureCase(path) {
  const memory = { user: [], account: [], session: [], verification: [] };
  const events = [];
  const options = (fields, joins = false) => ({
    database: memoryAdapter(memory),
    baseURL: "http://session-live-output.test",
    secret: "session-live-output-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: "serial", joins } },
    session: { additionalFields: fields },
  });
  const storedFields = { label: { type: "string" }, tail: { type: "string" } };
  const writer = await betterAuth(options(storedFields)).$context;
  const user = await writer.adapter.create({ model: "user", data: {
    name: "Session owner", email: "owner@session-live-output.test", emailVerified: false,
    image: null, createdAt, updatedAt: createdAt,
  } });
  assert.equal(user.id, "1");
  const reader = await betterAuth(options({
    label: { type: "string", transform: { async output(value) {
      const row = declarations.find(row => row.label === value);
      assert.ok(row, "The output callback must receive a declared session label");
      events.push(["label", value]);
      const updated = await writer.internalAdapter.updateSession(row.token, {
        id: row.id, expiresAt: changedExpiry, updatedAt: changedAt, tail: `after:${row.label}`,
      });
      assert.ok(updated, "The output callback must update the selected session");
      events.push(["write", row.label, observeValue(updated)]);
      return `${value}:out`;
    } } },
    tail: { type: "string", transform: { output(value) {
      events.push(["tail", value]);
      return `${value}:out`;
    } } },
  }, path === "get-native-join")).$context;
  const selected = path === "list" ? declarations : declarations.slice(0, 1);
  const first = selected[0];
  assert.ok(first, "Each scenario must select a session");
  if (path !== "create") {
    for (const row of selected) await writer.adapter.create({ model: "session", data: data(row, user.id) });
  }
  const before = observeValue(memory);
  let result;
  if (path === "create") {
    result = await reader.adapter.create({ model: "session", data: data(first, user.id) });
  } else if (path === "get-native-join") {
    result = await reader.internalAdapter.findSession(first.token);
  } else if (path === "list") {
    result = await reader.internalAdapter.listSessions(user.id);
  } else {
    result = await reader.internalAdapter.updateSession(first.token, { label: first.label, updatedAt: createdAt });
  }
  return { path, before, events, result: observeValue(result), after: observeValue(memory) };
}

export async function captureSessionLiveOutput() {
  const cases = [];
  for (const path of scenarios) cases.push(await captureCase(path));
  return { version, backend: "memory", idSlot: "implicit", cases };
}

if (import.meta.main) {
  assert.ok(process.argv[2], "Pass a fixture output path");
  writeFileSync(process.argv[2], `${JSON.stringify(await captureSessionLiveOutput(), null, 2)}\n`);
}
