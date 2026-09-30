import { expect } from "bun:test";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import { compatScenario } from "../../../support/scenario";
import { send } from "../email-otp/helpers";

compatScenario("user schema preserves transforms, visibility, validation and JWT claims through cached sessions", async (ctx) => {
  const post = (path: string, json: unknown, actor = "primary") => ctx.rawRequest({ path: `/api/auth${path}`, method: "POST", json, actor });
  const email = ctx.uniqueEmail("fields");
  const base = { email, password: "Password123!", name: "Field Owner" };
  const missing = await post("/sign-up/email", base);
  expect(missing.status).toBe(400);
  expect(missing.body).toMatchObject({ code: "MISSING_FIELD", message: "department is required" });
  const invalid = await post("/sign-up/email", { ...base, department: "engineering", score: -1 });
  expect(invalid.status).toBe(400);
  expect(invalid.body).toMatchObject({ code: "VALIDATION_ERROR", message: "score must be nonnegative" });
  const elevated = await post("/sign-up/email", { ...base, department: "engineering", role: "admin" });
  expect(elevated.status).toBe(400);
  expect(elevated.body).toMatchObject({ code: "FIELD_NOT_ALLOWED" });
  const proof = await post("/sign-up/email", { ...base, department: "engineering", phoneNumberVerified: true });
  expect(proof.status).toBe(400);
  expect(proof.body).toMatchObject({ code: "FIELD_NOT_ALLOWED", message: "phoneNumberVerified is not allowed to be set" });
  const signedUp = await post("/sign-up/email", { ...base, department: "engineering", alias: "owner", internalCode: "attacker", secretNote: "private", emailVerified: true, isAnonymous: true });
  expect(signedUp.status).toBe(200);
  const user = (signedUp.body as any).user;
  expect(user).toMatchObject({ department: "engineering", alias: "owner:in:in:out", internalCode: "server", score: 1, role: "user", emailVerified: false, isAnonymous: false, changedMarker: "created" });
  expect(user).not.toHaveProperty("secretNote");
  expect(user).toMatchObject({ cohort: "factory", enabled: true, tags: ["starter"], ratings: [1, 2], preferences: { theme: "system" }, joinedAt: "2020-01-02T03:04:05.000Z", level: "basic", label: "public-label", optionalAlias: "undefined:in:out" });
  expect(user).not.toHaveProperty("storedLabel");
  const cached = await ctx.rawRequest({ path: "/api/auth/get-session" });
  expect(cached.status).toBe(200);
  expect((cached.body as any).user).toEqual(user);
  const stored = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true" });
  expect(stored.status).toBe(200);
  expect((stored.body as any).user).toEqual(user);
  const forbidden = await post("/update-user", { internalCode: "attacker", department: "blocked" });
  expect(forbidden.status).toBe(400);
  expect(forbidden.body).toMatchObject({ code: "FIELD_NOT_ALLOWED" });
  const role = await post("/update-user", { role: "admin" });
  expect(role.status).toBe(400);
  expect(role.body).toMatchObject({ code: "FIELD_NOT_ALLOWED" });
  const unchanged = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true" });
  expect((unchanged.body as any).user.changedMarker).toBe("created");
  const update = await post("/update-user", { department: "research", alias: "changed", secretNote: "updated" });
  expect(update.status).toBe(200);
  const updated = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true" });
  expect((updated.body as any).user).toMatchObject({ id: user.id, department: "research", alias: "changed:in:in:out", internalCode: "server", changedMarker: "updated" });
  expect((updated.body as any).user).not.toHaveProperty("secretNote");
  const keys = await ctx.rawRequest({ path: "/api/auth/jwks" });
  expect(keys.status).toBe(200);
  const issued = await ctx.rawRequest({ path: "/api/auth/token" });
  expect(issued.status).toBe(200);
  const { payload } = await jwtVerify((issued.body as any).token, createLocalJWKSet(keys.body as JSONWebKeySet), { issuer: ctx.baseURL, audience: ctx.baseURL });
  expect(payload).toMatchObject({ sub: user.id, department: "research", alias: "changed:in:in:out", internalCode: "server" });
  expect(payload).not.toHaveProperty("secretNote");
  const { iat, exp, iss, aud, sub, ...claims } = payload;
  return { missing, invalid, elevated, proof, signedUp, cached, stored, forbidden, role, unchanged, update, updated, claims, subjectMatches: sub === user.id, lifetime: exp! - iat! };
});

compatScenario("email OTP creation uses the same user schema and persists transformed additional fields", async (ctx) => {
  const email = ctx.uniqueEmail("otp-fields");
  const otp = await send(ctx, email, "sign-in");
  const created = await ctx.rawRequest({ path: "/api/auth/sign-in/email-otp", method: "POST", json: {
    email, otp, name: "OTP Fields", department: "support", alias: "otp", internalCode: "attacker", secretNote: "otp-private",
  } });
  expect(created.status).toBe(200);
  const user = (created.body as any).user;
  expect(user).toMatchObject({ email, emailVerified: true, department: "support", alias: "otp:in:in:out", internalCode: "server", optionalAlias: "undefined:in:out" });
  expect(user).not.toHaveProperty("secretNote");
  const stored = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true" });
  expect(stored.status).toBe(200);
  expect((stored.body as any).user).toEqual(user);
  return { created, stored };
});

compatScenario("user field storage types preserve application JSON and enum values without implicit validators", async (ctx) => {
  const fields = {
    department: "typed", enabled: false, tags: ["a", "b"], ratings: [0, 3.5], level: "unlisted",
    preferences: { user: { role: "application-role", phoneNumberVerified: true }, metadata: { hidden: "literal" }, permissions: ["read", "write"] },
    joinedAt: "2021-02-03T04:05:06.000Z", label: "mapped label", optionalAlias: null,
  };
  const created = await ctx.rawRequest({ path: "/api/auth/sign-up/email", method: "POST", json: { email: ctx.uniqueEmail("typed"), password: "Password123!", name: "Typed User", ...fields } });
  expect(created.status).toBe(200);
  const user = (created.body as any).user;
  expect(user).toMatchObject({ ...fields, cohort: "factory", optionalAlias: "null:in:in:out" });
  expect(user).not.toHaveProperty("storedLabel");
  const stored = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true" });
  expect(stored.status).toBe(200);
  expect((stored.body as any).user).toEqual(user);
  const explicit = await ctx.rawRequest({ path: "/api/auth/update-user", method: "POST", json: { changedMarker: "explicit" } });
  expect(explicit.status).toBe(200);
  const updated = await ctx.rawRequest({ path: "/api/auth/get-session?disableCookieCache=true" });
  expect((updated.body as any).user.changedMarker).toBe("explicit");
  return { created, stored, explicit, updated };
});

compatScenario("administrator writes bypass public input restrictions but preserve output visibility", async (ctx) => {
  const post = (path: string, json: unknown, actor = "primary") => ctx.rawRequest({ path: `/api/auth${path}`, method: "POST", json, actor });
  const email = ctx.uniqueEmail("fields-admin");
  const signedUp = await post("/sign-up/email", { email, password: "Password123!", name: "Field Admin", department: "operations" });
  expect(signedUp.status).toBe(200);
  expect((signedUp.body as any).user).toMatchObject({ alias: "guest:in:out", internalCode: "server", score: 1 });
  const denied = await post("/admin/create-user", { email: ctx.uniqueEmail("denied"), name: "Denied", data: { department: "sales" } });
  expect(denied.status).toBe(403);
  await ctx.promoteAdmin({ email });
  const signedIn = await ctx.actor("admin").client.signIn.email({ email, password: "Password123!" });
  expect(signedIn.error).toBeNull();
  const managedEmail = ctx.uniqueEmail("managed");
  const created = await post("/admin/create-user", { email: managedEmail, password: "Password123!", name: "Managed", data: { department: "sales", alias: "managed", internalCode: "trusted", secretNote: "classified", score: -3 } }, "admin");
  expect(created.status).toBe(200);
  const user = (created.body as any).user;
  expect(user).toMatchObject({ department: "sales", alias: "managed:in:out", internalCode: "trusted", score: -3 });
  expect(user).not.toHaveProperty("secretNote");
  const updated = await post("/admin/update-user", { userId: user.id, data: { alias: "managed-edit", internalCode: "trusted-edit", secretNote: "new-classified", score: -4, isAnonymous: true, phoneNumber: "+15551234567", phoneNumberVerified: true } }, "admin");
  expect(updated.status).toBe(200);
  expect(updated.body).toMatchObject({ id: user.id, alias: "managed-edit:in:out", internalCode: "trusted-edit", score: -4, isAnonymous: true, phoneNumber: "+15551234567", phoneNumberVerified: true });
  expect(updated.body).not.toHaveProperty("secretNote");
  const managed = await ctx.actor("managed").client.signIn.email({ email: managedEmail, password: "Password123!" });
  expect(managed.error).toBeNull();
  expect(managed.data?.user).toMatchObject({ id: user.id, isAnonymous: true, phoneNumber: "+15551234567", phoneNumberVerified: true });
  const disabledCached = await ctx.rawRequest({ path: "/__test/disabled/get-session", actor: "managed" });
  const disabledStored = await ctx.rawRequest({ path: "/__test/disabled/get-session?disableCookieCache=true", actor: "managed" });
  expect(disabledCached.status).toBe(200);
  expect((disabledCached.body as any).user).toEqual(JSON.parse(JSON.stringify(managed.data?.user)));
  expect(disabledStored.status).toBe(200);
  expect((disabledStored.body as any).user).toMatchObject({ id: user.id, department: "sales", alias: "managed-edit:in:out" });
  for (const field of ["isAnonymous", "phoneNumber", "phoneNumberVerified", "role", "banned", "username", "twoFactorEnabled", "secretNote"]) expect((disabledStored.body as any).user).not.toHaveProperty(field);
  const hiddenCached = await ctx.rawRequest({ path: "/__test/hidden/get-session", actor: "managed" });
  const hiddenStored = await ctx.rawRequest({ path: "/__test/hidden/get-session?disableCookieCache=true", actor: "managed" });
  for (const result of [hiddenCached, hiddenStored]) {
    expect(result.status).toBe(200);
    expect((result.body as any).user.id).toBe(user.id);
    expect((result.body as any).user).not.toHaveProperty("department");
    expect((result.body as any).user).not.toHaveProperty("alias");
    expect((result.body as any).user).not.toHaveProperty("secretNote");
  }
  return { signedUp, denied, signedIn, created, updated, managed, disabledCached, disabledStored, hiddenCached, hiddenStored };
});
