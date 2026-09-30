import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asRecord, signUpUser } from "../../phase6/helpers";

compatScenario("JSON field decoding follows output callbacks and preserves route decoding boundaries", async (ctx) => {
  await signUpUser(ctx, "owner", "object-json-owner", "Owner");
  const observations: unknown[] = [];
  const post = async (path: string, json: unknown) => {
    const response = await ctx.rawRequest({ actor: "owner", path: `/api/auth/organization/${path}`, method: "POST", json });
    observations.push(response); return response;
  };
  const get = async (path: string) => {
    const response = await ctx.rawRequest({ actor: "owner", path: `/api/auth/organization/${path}`, method: "GET" });
    observations.push(response); return response;
  };
  const created = await post("create", { name: "JSON", slug: "json", metadata: { source: 1 } });
  expect(created.status).toBe(200);
  const organizationId = asRecord(created.body).id;
  expect(asRecord(created.body)).not.toHaveProperty("metadata");
  expect(asRecord((await get(`get-full-organization?organizationId=${organizationId}`)).body).metadata).toEqual({ visible: 1 });
  const updated = await post("update", { organizationId, data: { metadata: { source: 2, at: "2026-01-02T03:04:05Z" } } });
  expect(updated.status).toBe(200);
  expect(asRecord(updated.body).metadata).toEqual({ visible: 2, at: "2026-01-02T03:04:05.000Z" });
  expect(asRecord((await get(`get-full-organization?organizationId=${organizationId}`)).body).metadata).toEqual(asRecord(updated.body).metadata);
  const cleared = await post("update", { organizationId, data: { metadata: { clear: true } } });
  expect(cleared.status).toBe(200);
  expect(asRecord(cleared.body)).not.toHaveProperty("metadata");
  expect(asRecord((await get(`get-full-organization?organizationId=${organizationId}`)).body).metadata).toBeNull();
  const array = await post("create", { name: "Array", slug: "array", metadata: ["source", 2] });
  expect(array.status).toBe(200);
  expect(asRecord(array.body)).not.toHaveProperty("metadata");
  expect(asRecord((await get(`get-full-organization?organizationId=${asRecord(array.body).id}`)).body).metadata).toEqual(["visible", 2]);
  return observations;
});

compatScenario("JSON permission schema preserves create output and subsequent route parse errors", async (ctx) => {
  await signUpUser(ctx, "owner", "permission-json-owner", "Owner");
  const observations: unknown[] = [];
  const request = async (path: string, json?: unknown) => {
    const response = await ctx.rawRequest({ actor: "owner", path: `/api/auth/organization/${path}`, method: json ? "POST" : "GET", json });
    observations.push(response); return response;
  };
  const organization = await request("create", { name: "Roles", slug: "roles" });
  expect(organization.status).toBe(200);
  const organizationId = asRecord(organization.body).id;
  const created = await request("create-role", { organizationId, role: "json", permission: { member: ["create"] } });
  expect(created.status).toBe(200);
  const role = asRecord(asRecord(created.body).roleData);
  expect(role.permission).toEqual({ member: ["create"] });
  expect((await request(`get-role?organizationId=${organizationId}&roleId=${role.id}`)).status).toBe(500);
  expect((await request(`list-roles?organizationId=${organizationId}`)).status).toBe(500);
  expect((await request("update-role", { organizationId, roleId: role.id, data: { roleName: "renamed" } })).status).toBe(500);
  expect((await request("delete-role", { organizationId, roleId: role.id })).status).toBe(500);
  return observations;
});


compatScenario("JSON date revival normalizes valid overflow and retains invalid ISO strings", async (ctx) => {
  await signUpUser(ctx, "owner", "json-date-owner", "Owner");
  const metadata = {
    overflow: "2026-02-30T00:00:00Z",
    nested: ["0099-01-01T00:00:00Z", "2026-01-02T03:04:05.12345678901234567890Z", "2026-02-30T24:00:00Z"],
    untouched: ["2026-13-01T00:00:00Z", "2026-01-32T00:00:00Z", "2026-01-02T24:00:00.0001Z", "2026-01-02T03:04:60Z", "2026-01-02T03:04:05+00:00"],
  };
  const created = await ctx.rawRequest({ actor: "owner", path: "/api/auth/organization/create", method: "POST", json: { name: "Dates", slug: "dates", metadata } });
  expect(created.status).toBe(200);
  const read = await ctx.rawRequest({ actor: "owner", path: `/api/auth/organization/get-full-organization?organizationId=${asRecord(created.body).id}`, method: "GET" });
  expect(read.status).toBe(200);
  expect(asRecord(read.body).metadata).toEqual({
    overflow: "2026-03-02T00:00:00.000Z",
    nested: ["0099-01-01T00:00:00.000Z", "2026-01-02T03:04:05.123Z", "2026-03-03T00:00:00.000Z"],
    untouched: metadata.untouched,
  });
  return [created, read];
});
