import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { asArray, asRecord, signUpUser } from "../../phase6/helpers";
import { requests } from "../organization-extended/helpers";
import { configure, trace } from "./helpers";

compatScenario("organization metadata preserves empty and literal objects through writes, reads, deletes and hooks", async (ctx) => {
  await signUpUser(ctx, "owner", "metadata-owner", "Owner");
  const { call, observations } = requests(ctx);
  for (const [initial, next] of [[{}, { literal: "value" }], [{ literal: "value" }, {}]]) {
    await configure(ctx);
    const created = asRecord(await call("owner", "create", { name: "Metadata", slug: ctx.uniqueToken("metadata"), metadata: initial }));
    expect(created.metadata).toEqual(initial);
    const organizationId = created.id;
    const creation = await trace(ctx);
    expect(asRecord(creation.find((event) => event.event === "beforeCreateOrganization")!.organization).metadata).toEqual(initial);
    expect(asRecord(creation.find((event) => event.event === "afterCreateOrganization")!.organization).metadata).toEqual(initial);
    observations.push(creation);
    await configure(ctx);
    expect(asRecord(await call("owner", "update", { organizationId, data: { metadata: next } })).metadata).toEqual(next);
    const updated = await trace(ctx);
    expect(asRecord(updated.find((event) => event.event === "beforeUpdateOrganization")!.organization).metadata).toEqual(next);
    expect(asRecord(updated.find((event) => event.event === "afterUpdateOrganization")!.organization).metadata).toEqual(next);
    observations.push(updated);
    const stored = JSON.stringify(next);
    expect(asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`)).metadata).toBe(stored);
    expect(asArray(await call("owner", "list")).map(asRecord).find((org) => org.id === organizationId)!.metadata).toBe(stored);
    await configure(ctx);
    expect(asRecord(await call("owner", "delete", { organizationId })).metadata).toBe(stored);
    const deleted = await trace(ctx);
    expect(deleted.map((event) => event.event)).toEqual(["beforeDeleteOrganization", "afterDeleteOrganization"]);
    for (const event of deleted) expect(asRecord(event.organization).metadata).toBe(stored);
    observations.push(deleted);
  }
  return observations;
});

compatScenario("organization metadata distinguishes omitted values, invalid HTTP null and a null hook override", async (ctx) => {
  await signUpUser(ctx, "owner", "metadata-null-owner", "Owner");
  const { call, observations } = requests(ctx);
  const invalidCreate = asRecord(await call("owner", "create", { name: "Invalid", slug: ctx.uniqueToken("invalid-metadata"), metadata: null }, 400));
  expect(invalidCreate).toEqual({ code: "VALIDATION_ERROR", message: "[body.metadata] Invalid input: expected record, received null" });
  expect(await trace(ctx)).toEqual([]);
  const created = asRecord(await call("owner", "create", { name: "Absent", slug: ctx.uniqueToken("absent-metadata") }));
  expect(created).not.toHaveProperty("metadata");
  const organizationId = created.id;
  const creation = await trace(ctx);
  for (const event of creation.filter((event) => ["beforeCreateOrganization", "afterCreateOrganization"].includes(String(event.event)))) {
    expect(asRecord(event.organization)).not.toHaveProperty("metadata");
  }
  observations.push(creation);
  expect(asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`)).metadata).toBeNull();
  expect(asArray(await call("owner", "list")).map(asRecord).find((org) => org.id === organizationId)!.metadata).toBeNull();
  await configure(ctx);
  const invalidUpdate = asRecord(await call("owner", "update", { organizationId, data: { metadata: null } }, 400));
  expect(invalidUpdate).toEqual({ code: "VALIDATION_ERROR", message: "[body.data.metadata] Invalid input: expected record, received null" });
  expect(await trace(ctx)).toEqual([]);
  await configure(ctx, { metadataOverride: null });
  expect(asRecord(await call("owner", "update", { organizationId, data: { name: "Null" } })).metadata).toBeNull();
  const updated = await trace(ctx);
  expect(asRecord(updated.find((event) => event.event === "beforeUpdateOrganization")!.organization)).not.toHaveProperty("metadata");
  expect(asRecord(updated.find((event) => event.event === "afterUpdateOrganization")!.organization).metadata).toBeNull();
  observations.push(updated);
  expect(asRecord(await call("owner", `get-full-organization?organizationId=${organizationId}`)).metadata).toBe("null");
  expect(asArray(await call("owner", "list")).map(asRecord).find((org) => org.id === organizationId)!.metadata).toBe("null");
  await configure(ctx);
  expect(asRecord(await call("owner", "delete", { organizationId })).metadata).toBe("null");
  const deleted = await trace(ctx);
  for (const event of deleted) expect(asRecord(event.organization).metadata).toBe("null");
  observations.push(deleted);
  await configure(ctx, { metadataOverride: null });
  const cleared = asRecord(await call("owner", "create", { name: "Cleared", slug: ctx.uniqueToken("create-null-metadata"), metadata: { literal: "value" } }));
  expect(cleared).not.toHaveProperty("metadata");
  const clearedId = cleared.id;
  const clearedTrace = await trace(ctx);
  expect(asRecord(clearedTrace.find((event) => event.event === "beforeCreateOrganization")!.organization).metadata).toEqual({ literal: "value" });
  expect(asRecord(clearedTrace.find((event) => event.event === "afterCreateOrganization")!.organization)).not.toHaveProperty("metadata");
  observations.push(clearedTrace);
  expect(asRecord(await call("owner", `get-full-organization?organizationId=${clearedId}`)).metadata).toBeNull();
  expect(asArray(await call("owner", "list")).map(asRecord).find((org) => org.id === clearedId)!.metadata).toBeNull();
  await configure(ctx);
  expect(asRecord(await call("owner", "delete", { organizationId: clearedId })).metadata).toBeNull();
  const clearedDelete = await trace(ctx);
  for (const event of clearedDelete) expect(asRecord(event.organization).metadata).toBeNull();
  observations.push(clearedDelete);
  return observations;
});
