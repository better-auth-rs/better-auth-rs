import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";

const models = ["organization", "team", "member", "invitation", "organizationRole"];
const fields = {
  organization: ["logo", "name"],
  team: ["name"],
  member: ["role"],
  invitation: ["status", "role"],
  organizationRole: ["role"],
};

async function capture(backend, model, mode) {
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events = [];
  const policy = (field) => ({
    type: "string", required: false,
    transform: {
      input(value) { events.push([field, "input", value]); return value.trim(); },
      output(value) {
        events.push([field, "output", value]);
        return ["name", "logo", "label"].includes(field) ? `${value}:out` : value;
      },
    },
  });
  const declared = {
    label: { ...policy("label"),
      defaultValue() { events.push(["label", "default"]); return " Label "; },
      onUpdate() { events.push(["label", "onUpdate"]); return " Updated "; },
    },
    ...Object.fromEntries(fields[model].map(field => [field, policy(field)])),
  };
  if (model === "organization") {
    declared.logo.defaultValue = () => { events.push(["logo", "default"]); return " Logo "; };
    declared.logo.onUpdate = () => { events.push(["logo", "onUpdate"]); return " Next Logo "; };
  }
  const own = organization({
    teams: { enabled: true }, dynamicAccessControl: { enabled: true },
    schema: { [model]: { additionalFields: mode === "direct" ? declared : Object.fromEntries(
      Object.entries(declared).filter(([field]) => field !== "label"),
    ) } },
  });
  const custom = { id: "ordinary-order-fields", schema: { [model]: { fields: { label: declared.label } } } };
  const options = {
    database, baseURL: "http://organization-order.test",
    secret: "ordinary-organization-order-secret-at-least-32-characters",
    telemetry: { enabled: false }, logger: { disabled: true },
    plugins: mode === "direct" ? [own] : mode === "before" ? [custom, own] : [own, custom],
  };
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const { adapter } = await betterAuth(options).$context;
    const createdAt = new Date("2025-01-01T00:00:00.000Z");
    const user = await adapter.create({ model: "user", data: {
      name: "Fixture", email: "ordinary@order.test", emailVerified: false, createdAt, updatedAt: createdAt,
    } });
    const parent = model === "organization" ? undefined : await adapter.create({ model: "organization", data: {
      name: "Parent", slug: "parent", createdAt,
    } });
    const input = {
      organization: { name: " Acme ", slug: "acme", createdAt },
      team: { name: " Team ", organizationId: parent?.id, createdAt },
      member: { role: "member", organizationId: parent?.id, userId: user.id, createdAt },
      invitation: { role: "member", status: "pending", organizationId: parent?.id, inviterId: user.id,
        email: "invitee@order.test", createdAt, expiresAt: new Date("2030-01-01T00:00:00.000Z") },
      organizationRole: { role: "reader", permission: JSON.stringify({ organization: ["read"] }), organizationId: parent?.id },
    }[model];
    const visible = (row) => Object.fromEntries(["label", ...fields[model]].map(field => [field, row[field]]));
    const created = await adapter.create({ model, data: input });
    const patch = {
      organization: { name: " Renamed " }, team: { name: " Next " }, member: { role: "member" },
      invitation: { status: "pending" }, organizationRole: { role: "reader" },
    }[model];
    const updated = await adapter.update({ model, where: [{ field: "id", value: created.id }], update: patch });
    const found = await adapter.findOne({ model, where: [{ field: "id", value: created.id }] });
    return { backend, model, mode, created: visible(created), updated: visible(updated), found: visible(found), events };
  } finally { database?.close(); }
}

const cases = [];
for (const backend of ["memory", "sqlite"]) {
  for (const model of models) cases.push(await capture(backend, model, "direct"));
  for (const mode of ["before", "after"]) cases.push(await capture(backend, "organization", mode));
}
const result = { version: "1.7.6", cases };
const fixture = new URL("../../../tests/fixtures/organization-direct-order-1.7.6.json", import.meta.url);
if (process.env.ORGANIZATION_DIRECT_ORDER_OUTPUT) {
  writeFileSync(process.env.ORGANIZATION_DIRECT_ORDER_OUTPUT, `${JSON.stringify(result, null, 2)}\n`);
} else {
  assert.deepStrictEqual(result, JSON.parse(readFileSync(fixture, "utf8")));
}
console.log(`Organization declaration order: ${cases.length} contracts`);
