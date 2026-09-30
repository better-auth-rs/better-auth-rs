import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser, type CompatContext } from "../../phase6/helpers";

function calls(ctx: CompatContext) {
  const observations: unknown[] = [];
  return {
    observations,
    async post(path: string, json: unknown) {
      const response = await ctx.rawRequest({ actor: "owner", path: `/api/auth/organization/${path}`, method: "POST", json });
      observations.push(response); return response;
    },
    async get(path: string) {
      const response = await ctx.rawRequest({ actor: "owner", path: `/api/auth/organization/${path}`, method: "GET" });
      observations.push(response); return response;
    },
  };
}

compatScenario("organization metadata policies receive JSON text and retain route-specific decoding", async (ctx) => {
  await signUpUser(ctx, "owner", "json-owner", "Owner");
  const api = calls(ctx);
  const created = await api.post("create", { name: "Native", slug: "native", metadata: '{"source":1}' });
  expect(created.status).toBe(200);
  const organization = asRecord(created.body);
  expect(organization.metadata).toEqual({ visible: 1 });
  const id = organization.id as string;
  expect(asRecord((await api.get(`get-full-organization?organizationId=${id}`)).body).metadata).toBe('"{\\"visible\\":1}"');
  const updated = await api.post("update", { organizationId: id, data: { metadata: { source: 2 } } });
  expect(updated.status).toBe(200);
  expect(asRecord(updated.body).metadata).toEqual({ visible: 2 });
  expect(asRecord((await api.get(`get-full-organization?organizationId=${id}`)).body).metadata).toBe('{"visible":2}');
  const dates = await api.post("update", { organizationId: id, data: { metadata: { fraction: "2026-01-02T03:04:05.1234Z", overflow: "2026-02-30T25:00:00+02:00", year: "0099-01-01T00:00:00Z" } } });
  expect(dates.status).toBe(200);
  expect(asRecord(dates.body).metadata).toEqual({ fraction: "2026-01-02T03:04:06.234Z", overflow: "2026-03-02T23:00:00.000Z", year: "1999-01-01T00:00:00.000Z" });
  const cleared = await api.post("update", { organizationId: id, data: { metadata: { clear: true } } });
  expect(asRecord(cleared.body).metadata).toBeNull();
  expect(asRecord((await api.get(`get-full-organization?organizationId=${id}`)).body).metadata).toBe("null");
  const defaulted = await api.post("create", { name: "Default", slug: "default" });
  expect(asRecord(defaulted.body).metadata).toEqual({ visible: "default" });
  const invalid = await api.post("update", { organizationId: id, data: { metadata: "invalid" } });
  expect(invalid.status).toBe(400);
  expect((await api.post("update", { organizationId: id, data: { metadata: null } })).status).toBe(400);
  return api.observations;
});

compatScenario("role permission transforms preserve nested overrides and original response permissions", async (ctx) => {
  await signUpUser(ctx, "owner", "role-json-owner", "Owner");
  const api = calls(ctx);
  const organizationId = asRecord((await api.post("create", { name: "Roles", slug: "roles" })).body).id;
  const original = { member: ["create"] };
  const created = await api.post("create-role", { organizationId, role: "original", permission: original,
    additionalFields: { role: "nested", permission: '{"team":["create"]}', id: "ignored-create-id" } });
  expect(created.status).toBe(200);
  const role = asRecord(asRecord(created.body).roleData);
  expect(role.role).toBe("nested");
  expect(role.id).not.toBe("ignored-create-id");
  expect(role.permission).toEqual(original);
  const id = role.id as string;
  const selected = await api.get(`get-role?organizationId=${organizationId}&roleId=${id}`);
  expect(asRecord(selected.body).permission).toEqual({ team: ["update"] });
  const updated = await api.post("update-role", { organizationId, roleId: id, data: { roleName: "rename", role: "ignored-by-role-name", permission: null } });
  expect(updated.status).toBe(200);
  expect(asRecord(asRecord(updated.body).roleData).role).toBe("rename");
  expect(asRecord(asRecord(updated.body).roleData).permission).toEqual({ team: ["update"] });
  const listed = await api.get(`list-roles?organizationId=${organizationId}`);
  expect(asRecord(asArray(listed.body)[0]).permission).toEqual({ member: ["update"] });
  const invalid = await api.post("update-role", { organizationId, roleId: id, data: { permission: '{}' } });
  expect(invalid.status).toBe(400);
  expect(asRecord(invalid.body).code).toBe("INVALID_RESOURCE");
  const renamedId = await api.post("update-role", { organizationId, roleId: id, data: { id: "replacement-role-id", role: "raw-name" } });
  expect(renamedId.status).toBe(200);
  expect(asRecord(asRecord(renamedId.body).roleData).id).toBe("replacement-role-id");
  expect(asRecord((await api.get(`get-role?organizationId=${organizationId}&roleId=replacement-role-id`)).body).role).toBe("raw-name");
  return api.observations;
});

compatScenario("invalid decoded permissions retain the upstream role-specific API error", async (ctx) => {
  await signUpUser(ctx, "owner", "invalid-permission-owner", "Owner");
  const api = calls(ctx);
  const organizationId = asRecord((await api.post("create", { name: "Invalid permission", slug: "invalid-permission" })).body).id;
  const created = await api.post("create-role", { organizationId, role: "broken", permission: { member: ["create"] }, additionalFields: { permission: "false" } });
  expect(created.status).toBe(200);
  const selected = await api.get(`get-role?organizationId=${organizationId}&roleName=broken`);
  expect(selected.status).toBe(500);
  expect(selected.body).toEqual({ message: "Invalid permissions for role broken" });
  return api.observations;
});
