import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

const profile = process.env.COMPAT_PROFILE;
const password = "AdminOptions123!";
async function control(ctx: any, body: any) {
  const response = await fetch(`${ctx.baseURL}/__test/admin-options`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  expect(response.status).toBe(200);
  return response.json();
}
async function post(ctx: any, actor: any, path: string, body: any) {
  const response = await actor.fetch(`${ctx.baseURL}/api/auth${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : "" };
}
async function account(ctx: any, key: string, role?: string) {
  const actor = ctx.actor(key), email = ctx.uniqueEmail(key);
  const signed = await actor.client.signUp.email({ email, password, name: key });
  expect(signed.error).toBeNull();
  if (role) await control(ctx, { email, patch: { role } });
  return { actor, email, id: signed.data.user.id };
}

compatScenario("omitted and empty admin roles preserve distinct permission maps", async ctx => {
  const acting = await account(ctx, "roles-admin", profile === "admin-options" ? "manager" : "admin");
  const target = await account(ctx, "roles-target");
  const permission = await post(ctx, acting.actor, "/admin/has-permission", { permissions: { user: ["set-email"] } });
  const changed = await post(ctx, acting.actor, "/admin/update-user", { userId: target.id, data: { email: target.email.toUpperCase() } });
  expect(permission.status).toBe(200);
  expect(permission.body.success).toBe(profile !== "admin-empty-roles");
  expect(changed.status).toBe(profile === "admin-empty-roles" ? 403 : 200);
  const stored = await control(ctx, { email: target.email });
  expect(stored.user.email).toBe(target.email);
  return { permission, changed, stored };
}, 30_000);

compatScenario("admin role validation distinguishes omitted options and explicit empty lists", async ctx => {
  const inputs = [{}, { roles: {} }, { roles: {}, adminRoles: [] }, { roles: {}, adminRoles: ["admin"] }, { roles: { custom: {} }, adminRoles: ["CUSTOM"] }];
  const results = [];
  for (const options of inputs) results.push(await control(ctx, { action: "validate", options }));
  expect(results.map(item => item.valid)).toEqual([true, true, true, false, true]);
  expect(results[3].message).toBe("Invalid admin roles: admin. Admin roles must be defined in the 'roles' configuration.");
  return results;
});

if (profile === "admin-options") {
  compatScenario("native administrator creation distinguishes omitted and empty headers", async ctx => {
    const email = ctx.uniqueEmail("native-admin");
    const created = await control(ctx, { action: "native-create", input: { email, name: "Native", password, role: "admin", data: { banned: true, banReason: "native", banExpires: "2030-01-01T00:00:00.000Z" } } });
    expect(created.result.user).toMatchObject({ email, role: "admin", banned: true, banReason: "native" });
    const state = await control(ctx, { email });
    expect(state.sessions).toBe(0); expect(state.user.hasBanExpires).toBe(true);
    await control(ctx, { email, patch: { banned: false, banReason: null, banExpires: null } });
    const signed = await post(ctx, ctx.actor("native-created-signin"), "/sign-in/email", { email, password });
    expect(signed.status).toBe(200); expect(signed.body.user.id).toBe(created.result.user.id);
    const rejectedEmail = ctx.uniqueEmail("native-rejected");
    const rejected = await control(ctx, { action: "native-create", headers: {}, input: { email: rejectedEmail, name: "Rejected" } });
    expect(rejected.error).toEqual({ kind: "api", status: 401, body: null });
    expect((await control(ctx, { email: rejectedEmail })).user).toBeNull();
    return { created, state, signed, rejected };
  }, 30_000);

  compatScenario("ban null patches clear only the supplied fields", async ctx => {
    const manager = await account(ctx, "nullable-manager", "manager");
    const target = await account(ctx, "nullable-target");
    await control(ctx, { email: target.email, patch: { banned: true, banReason: "review", banExpires: "2030-01-01T00:00:00.000Z" } });
    const responses = [];
    for (const data of [{ banned: false }, { banReason: null }, { banExpires: null }]) {
      const response = await post(ctx, manager.actor, "/admin/update-user", { userId: target.id, data });
      expect(response.status).toBe(200); responses.push(response);
    }
    expect(responses[0].body).toMatchObject({ banned: false, banReason: "review", banExpires: "2030-01-01T00:00:00.000Z" });
    expect(responses[1].body).toMatchObject({ banReason: null, banExpires: "2030-01-01T00:00:00.000Z" });
    expect(responses[2].body).toMatchObject({ banReason: null, banExpires: null });
    const state = await control(ctx, { email: target.email });
    expect(state.user.banReason).toBeNull(); expect(state.user.hasBanExpires).toBe(false); expect(state.sessions).toBe(1);
    return { responses, state };
  }, 30_000);
  compatScenario("sensitive create and update fields require their separate grants before writes", async ctx => {
    const acting = await account(ctx, "editor", "editor");
    const target = await account(ctx, "sensitive-target");
    const denied = [];
    for (const data of [{ emailVerified: false }, { email: null }, { banned: false }, { banReason: null }, { banExpires: null }, { role: "user" }]) {
      const result = await post(ctx, acting.actor, "/admin/update-user", { userId: target.id, data });
      expect(result.status).toBe(403); denied.push(result);
    }
    for (const data of [{ role: "user" }, { banned: true }, { banReason: "policy" }, { banExpires: "2030-01-01T00:00:00.000Z" }]) {
      const email = ctx.uniqueEmail("denied-create");
      const result = await post(ctx, acting.actor, "/admin/create-user", { email, name: "Denied", data });
      expect(result.status).toBe(403);
      expect((await control(ctx, { email })).user).toBeNull(); denied.push(result);
    }
    const rejectedPassword = await post(ctx, acting.actor, "/admin/update-user", { userId: target.id, data: { password: null, banned: true } });
    expect(rejectedPassword.status).toBe(400);
    expect(rejectedPassword.body.code).toBe("PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER");
    const stored = await control(ctx, { email: target.email });
    expect(stored.user.banned).toBe(false); expect(stored.sessions).toBe(1);
    return { denied, rejectedPassword, stored };
  }, 30_000);

  compatScenario("authorized role creation and admin impersonation preserve stored identity", async ctx => {
    const manager = await account(ctx, "manager", "manager");
    const email = ctx.uniqueEmail("created-admin");
    const created = await post(ctx, manager.actor, "/admin/create-user", { email, name: "Created", password, role: "user", data: { role: "admin", banned: true, banReason: "review", banExpires: "2030-01-01T00:00:00.000Z" } });
    expect(created.status).toBe(200); expect(created.body.user).toMatchObject({ role: "user", banned: true, banReason: "review" });
    const snapshot = await control(ctx, { email });
    expect(snapshot.user.hasBanExpires).toBe(true);
    const admin = await account(ctx, "admin-target", "admin");
    const editor = await account(ctx, "impersonation-editor", "editor");
    const denied = await post(ctx, editor.actor, "/admin/impersonate-user", { userId: admin.id });
    expect(denied.status).toBe(403); expect(denied.body.code).toBe("YOU_CANNOT_IMPERSONATE_ADMINS");
    const allowed = await post(ctx, manager.actor, "/admin/impersonate-user", { userId: admin.id });
    expect(allowed.status).toBe(200); expect(allowed.body.session.impersonatedBy).toBe(manager.id);
    return { created, snapshot, denied, allowed };
  }, 30_000);

  compatScenario("ban updates persist before after hooks and revoke sessions only after hooks succeed", async ctx => {
    const acting = await account(ctx, "ban-manager", "manager");
    const target = await account(ctx, "ban-target");
    await control(ctx, { clear: true, afterMode: "reject" });
    const rejected = await post(ctx, acting.actor, "/admin/update-user", { userId: target.id, data: { banned: true } });
    expect(rejected.status).toBe(400); expect(rejected.body.code).toBe("AFTER_UPDATE_REJECTED");
    const preserved = await control(ctx, { email: target.email });
    expect(preserved.user.banned).toBe(true); expect(preserved.sessions).toBe(1);
    expect(preserved.events).toEqual([{ event: "user-updated", banned: true, sessions: 1 }]);
    await control(ctx, { clear: true, afterMode: "" });
    const accepted = await post(ctx, acting.actor, "/admin/update-user", { userId: target.id, data: { banned: true } });
    expect(accepted.status).toBe(200);
    const revoked = await control(ctx, { email: target.email });
    expect(revoked.sessions).toBe(0); expect(revoked.events).toEqual([{ event: "user-updated", banned: true, sessions: 1 }]);
    const selfBan = await post(ctx, acting.actor, "/admin/update-user", { userId: acting.id, data: { banned: true } });
    expect(selfBan.status).toBe(400); expect(selfBan.body.code).toBe("YOU_CANNOT_BAN_YOURSELF");
    return { rejected, preserved, accepted, revoked, selfBan };
  }, 30_000);

  compatScenario("asynchronous banned messages see private fields and failures never create sessions", async ctx => {
    const target = await account(ctx, "message-target");
    await control(ctx, { email: target.email, patch: { banned: true, banReason: "review" }, clear: true });
    const results = [];
    for (const mode of ["", "api-error", "ordinary-error"]) {
      await control(ctx, { mode, clear: true });
      const result = await post(ctx, ctx.actor(`message-${mode}`), "/sign-in/email", { email: target.email, password });
      expect(result.status).toBe(mode === "" ? 403 : mode === "api-error" ? 400 : 500);
      if (mode === "") expect(result.body).toEqual({ code: "BANNED_USER", message: `Blocked: ${target.email}/admin-hidden` });
      if (mode === "ordinary-error") expect(result.body).toBe("");
      const native = await control(ctx, { action: "native-sign-in", input: { email: target.email, password }, clear: true });
      if (mode === "ordinary-error") expect(native.error).toEqual({ kind: "error", message: "private admin callback failure" });
      else expect(native.error).toEqual({ kind: "api", status: result.status, body: result.body });
      const state = await control(ctx, { email: target.email });
      expect(state.sessions).toBe(1);
      expect(state.events).toEqual([{ event: "banned-message", email: target.email, reason: "review", secretNote: "admin-hidden" }]);
      results.push({ result, native, state });
    }
    await control(ctx, { email: target.email, patch: { banExpires: "2000-01-01T00:00:00.000Z" }, clear: true });
    const expired = await post(ctx, ctx.actor("expired-ban"), "/sign-in/email", { email: target.email, password });
    expect(expired.status).toBe(200);
    const final = await control(ctx, { email: target.email });
    expect(final.events).toEqual([]); expect(final.user.banned).toBe(false); expect(final.sessions).toBe(2);
    return { results, expired, final };
  }, 30_000);
}
