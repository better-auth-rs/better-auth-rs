import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { control } from "../secondary-common/scenarios";

export function sessionFieldScenarios(mode: "database" | "cache" | "both") {
  const database = mode !== "cache";
  const cache = mode !== "database";
  compatScenario("session field policies preserve adapter and cache transformation boundaries", async ctx => {
    const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("session-fields"), password: "Password123!", name: "Fields" });
    expect(signup.error).toBeNull();
    const initial = await ctx.rawRequest({ path: "/api/auth/get-session" });
    const initialSession = (initial.body as any).session;
    expect(initialSession.deviceLabel).toBe(database ? "factory:input:output" : "factory");
    expect(initialSession.settings).toEqual(database ? { stage: "created", output: true } : { stage: "created" });
    expect(initialSession).not.toHaveProperty("internalNote");
    expect(initialSession.validatedLabel).toBe(database ? null : undefined);
    const update = await ctx.rawRequest({ path: "/api/auth/update-session", method: "POST", json: { deviceLabel: "laptop" } });
    expect(update.status).toBe(200);
    expect((update.body as any).session.deviceLabel).toBe(database ? "laptop:input:input:output" : "laptop:input");
    const read = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect((read.body as any).session.deviceLabel).toBe(cache ? "laptop:input" : "laptop:input:input:output");
    const validated = await ctx.rawRequest({ path: "/api/auth/update-session", method: "POST", json: { validatedLabel: "ok" } });
    expect(validated.status).toBe(200);
    expect((validated.body as any).session.validatedLabel).toBe(database ? "ok:validated:input:output" : "ok:validated");
    expect((validated.body as any).session.deviceLabel).toBe(database ? "tick:input:output" : "laptop:input");
    const invalid = await ctx.rawRequest({ path: "/api/auth/update-session", method: "POST", json: { validatedLabel: "x" } });
    expect(invalid.status).toBe(400);
    expect(invalid.body).toEqual({ code: "VALIDATION_ERROR", message: "label too short" });
    const protectedField = await ctx.rawRequest({ path: "/api/auth/update-session", method: "POST", json: { internalNote: "client" } });
    expect(protectedField.status).toBe(400);
    expect(protectedField.body).toEqual({ code: "FIELD_NOT_ALLOWED", message: "internalNote is not allowed to be set" });
    const settings = await ctx.rawRequest({ path: "/api/auth/update-session", method: "POST", json: { settings: { stage: "updated" }, internalNote: false } });
    expect(settings.status).toBe(200);
    expect((settings.body as any).session.settings).toEqual(database ? { stage: "updated", output: true } : { stage: "updated" });
    const listed = await ctx.rawRequest({ path: "/api/auth/list-sessions" });
    expect((listed.body as any[])[0].settings).toEqual(cache ? { stage: "updated" } : { stage: "updated", output: true });
    expect((listed.body as any[])[0]).not.toHaveProperty("internalNote");
    return { initial, update, read, validated, invalid, protectedField, settings, listed };
  });
  if (cache) compatScenario("secondary session refresh returns the adapter update without transforming a cached snapshot again", async ctx => {
    const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("refresh-fields"), password: "Password123!", name: "Refresh Fields" });
    expect(signup.error).toBeNull();
    const token = signup.data!.token!;
    const state = await control(ctx);
    const entry = state.entries.find((entry: any) => entry.key === token);
    const snapshot = JSON.parse(entry.value);
    snapshot.session.expiresAt = new Date(Date.now() + 60000).toISOString();
    await control(ctx, { action: "put", key: token, value: JSON.stringify(snapshot) });
    const refreshed = await ctx.rawRequest({ path: "/api/auth/get-session" });
    expect(refreshed.status).toBe(200);
    expect((refreshed.body as any).session.deviceLabel).toBe(database ? "tick:input:output" : "factory");
    const read = await ctx.rawRequest({ path: "/api/auth/get-session?disableRefresh=true" });
    expect((read.body as any).session.deviceLabel).toBe(database ? "factory:input:output" : "factory");
    return { refreshed, read };
  });
}
