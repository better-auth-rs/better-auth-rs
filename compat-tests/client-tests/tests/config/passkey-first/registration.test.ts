import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { signUpUser } from "../../phase6/helpers";
import { asArray, asRecord, authenticator, fixture } from "../passkey-options/helpers";

compatScenario("Passkey-first registration resolves an identity and creates a user, credential and session atomically", async (ctx) => {
  const f = fixture(ctx); const key = authenticator("passkey-first-success");
  const userId = "passkey-created-user";
  await f.control({ createUser: { id: userId, email: ctx.uniqueEmail("passkey-first"), name: "Created User", emailVerified: false }, targetUserId: userId, updateUserName: "Updated User", deleteTemporary: true });
  const options = await f.options("primary", "?context=signup-intent");
  expect(asRecord(options.user)).toMatchObject({ name: "Resolved User", displayName: "Resolved Display" });
  const registered = await f.register(key, options, { createSession: true });
  expect(registered.status).toBe(200);
  expect(asRecord(registered.body).name).toBe("Hook Key");
  expect(asRecord(registered.body).userId).toBe(userId);
  expect(asRecord(asRecord(registered.body).user).id).toBe(userId);
  const session = await ctx.actor().client.getSession();
  expect(session.data!.user.id).toBe(userId); f.observations.push(ctx.snapshot(session));
  const state = await f.trace(userId);
  expect(state.user).toBe(true); expect(asArray(state.passkeys)).toHaveLength(1);
  const events = asArray(state.events).map(asRecord);
  expect(events.map((event) => event.event)).toEqual(["resolve", "registration.extensions", "registration.verified", "users", "users.deleted", "session.before", "session.after"]);
  expect(events[3]).toEqual({ event: "users", found: true, name: "Updated User" });
  expect(events[4]).toEqual({ event: "users.deleted", missing: true });
  expect(asRecord(asRecord(registered.body).user).name).toBe("Updated User");
  expect(events[2]).toMatchObject({ context: "signup-intent", user: { id: "provisional-user", name: "Resolved User", displayName: "Resolved Display" }, createSession: true });
  return f.observations;
});

compatScenario("Passkey createSession rolls back user and credential writes when session creation fails", async (ctx) => {
  const f = fixture(ctx); const userId = "passkey-rollback-user";
  await f.control({ createUser: { id: userId, email: ctx.uniqueEmail("passkey-rollback"), name: "Rollback User", emailVerified: false }, targetUserId: userId, failSession: true });
  const key = authenticator("passkey-rollback-key");
  const options = await f.options();
  const failed = await f.register(key, options, { createSession: true });
  expect(failed.status).toBe(403); expect(asRecord(failed.body).code).toBe("SESSION_REJECTED");
  const state = await f.trace(userId);
  expect(state.user).toBe(false); expect(state.passkeys).toEqual([]);
  const replay = await f.register(key, options, { createSession: true });
  expect(replay.status).toBe(400); expect(asRecord(replay.body).code).toBe("CHALLENGE_NOT_FOUND");
  await f.control({ failSession: false });
  expect((await f.register(key, await f.options(), { createSession: true })).status).toBe(200);
  expect((await f.trace(userId)).user).toBe(true);
  return f.observations;
});

compatScenario("Passkey optional sessions bypass identity resolution and preserve nontransactional hook writes", async (ctx) => {
  const f = fixture(ctx);
  await f.control({ invalidUser: true });
  const invalid = await ctx.rawRequest({ path: "/api/auth/passkey/generate-register-options" });
  expect(invalid.status).toBe(400); expect(asRecord(invalid.body).code).toBe("RESOLVED_USER_INVALID"); f.observations.push(invalid);
  expect(asArray((await f.trace()).events)).toHaveLength(1);
  const userId = "passkey-nontransaction-user";
  await f.control({ invalidUser: false, registrationMode: "api-error", createUser: { id: userId, email: ctx.uniqueEmail("passkey-no-transaction"), name: "Nontransaction User", emailVerified: false } });
  expect((await f.register(authenticator("passkey-no-transaction"), await f.options())).status).toBe(403);
  const state = await f.trace(userId); expect(state.user).toBe(true); expect(state.passkeys).toEqual([]);
  const owner = await signUpUser(ctx, "primary", "passkey-existing", "Owner");
  await f.control({ invalidUser: true, resolveMode: "error" });
  const options = await f.options();
  expect(asRecord(options.user).name).toBe(owner.email);
  expect(asArray((await f.trace()).events).map(asRecord).map((event) => event.event)).toEqual(["registration.extensions"]);
  return f.observations;
});

compatScenario("Passkey cancelled session rolls back registration and consumes the challenge", async (ctx) => {
  const f = fixture(ctx); const userId = "passkey-cancelled-user";
  await f.control({ createUser: { id: userId, email: ctx.uniqueEmail("passkey-cancelled"), name: "Cancelled User", emailVerified: false }, targetUserId: userId, cancelSession: true });
  const key = authenticator("passkey-cancelled-key");
  const options = await f.options();
  const failed = await f.register(key, options, { createSession: true });
  expect(failed.status).toBe(500);
  expect(failed.body).toEqual({ code: "UNABLE_TO_CREATE_SESSION", message: "Unable to create session" });
  const state = await f.trace(userId);
  expect(state.user).toBe(false); expect(state.passkeys).toEqual([]);
  expect(asArray(state.events).map(asRecord).map(event => event.event)).toEqual(["resolve", "registration.extensions", "registration.verified", "session.before"]);
  const session = await ctx.actor().client.getSession();
  expect(session.data).toBeNull(); f.observations.push(ctx.snapshot(session));
  const replay = await f.register(key, options, { createSession: true });
  expect(replay.status).toBe(400); expect(asRecord(replay.body).code).toBe("CHALLENGE_NOT_FOUND");
  await f.control({ cancelSession: false });
  expect((await f.register(key, await f.options(), { createSession: true })).status).toBe(200);
  expect((await f.trace(userId)).user).toBe(true);
  return f.observations;
});

compatScenario("Passkey session registration applies admin bans and expiry inside the transaction", async (ctx) => {
  const f = fixture(ctx);
  const userId = "passkey-banned-user";
  await f.control({ createUser: { id: userId, email: ctx.uniqueEmail("passkey-banned"), name: "Banned User", emailVerified: false, banned: true }, targetUserId: userId });
  const key = authenticator("passkey-banned");
  const denied = await f.register(key, await f.options(), { createSession: true });
  expect(denied.status).toBe(403); expect(asRecord(denied.body).code).toBe("BANNED_USER");
  const state = await ctx.rawRequest({ path: `/__test/passkey-options?userId=${userId}` });
  expect(asRecord(state.body).user).toBe(false); expect(asRecord(state.body).passkeys).toEqual([]);
  await f.control({ createUser: { id: userId, email: ctx.uniqueEmail("passkey-banned"), name: "Banned User", emailVerified: false, banned: true, banExpires: "2020-01-01T00:00:00.000Z" } });
  const allowed = await f.register(key, await f.options(), { createSession: true });
  expect(allowed.status).toBe(200);
  const session = await ctx.actor().client.getSession();
  expect(session.data!.user.banned).toBe(false); f.observations.push(ctx.snapshot(session));
  return f.observations;
});
