import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { signUpUser } from "../../phase6/helpers";
import { asArray, asRecord, authenticator, fixture } from "./helpers";

compatScenario("Passkey options use application RP name, selection, request extensions and custom challenge cookie", async (ctx) => {
  const owner = await signUpUser(ctx, "primary", "passkey-options", "Owner");
  const f = fixture(ctx); await f.control();
  const options = await f.options("primary", "?name=Custom%20Account&context=registration-context&authenticatorAttachment=cross-platform");
  expect(options.rp).toEqual({ id: "localhost", name: "Passkey Configuration" });
  expect(options.authenticatorSelection).toEqual({ authenticatorAttachment: "cross-platform", residentKey: "required", requireResidentKey: true, userVerification: "required" });
  expect(asRecord(options).extensions).toEqual({ credProps: true, largeBlob: { support: "preferred" } });
  const key = authenticator("passkey-options-key");
  const registered = await f.register(key, options, { name: "  \uFEFFClient Key\uFEFF  " }, "primary", "https://secondary.example");
  expect(registered.status).toBe(200); expect(asRecord(registered.body).name).toBe("Client Key");
  let trace = asArray((await f.trace()).events).map(asRecord);
  expect(trace.map((event) => event.event)).toEqual(["registration.extensions", "registration.verified"]);
  expect(trace[1]).toMatchObject({ context: "registration-context", user: { id: owner.signup.data!.user.id, name: owner.email, displayName: owner.email }, name: "Client Key", verified: true, info: { userVerified: false, origin: "https://secondary.example", rpID: "localhost" } });
  const authOptions = await f.authenticationOptions();
  const signed = key.authenticate(authOptions, "https://passkeys.example", 1, 0x01, options.user.id);
  const loggedIn = await ctx.rawRequest({ actor: "login", path: "/api/auth/passkey/verify-authentication", method: "POST", json: { response: signed } });
  expect(loggedIn.status).toBe(200); f.observations.push(loggedIn);
  trace = asArray((await f.trace()).events).map(asRecord);
  expect(trace.slice(-3).map((event) => event.event)).toEqual(["authentication.verified", "session.before", "session.after"]);
  expect(trace.at(-3)).toMatchObject({ verified: true, info: { newCounter: 1, userVerified: false, origin: "https://passkeys.example", rpID: "localhost" } });

  await f.control();
  const backupOptions = await f.authenticationOptions("backup-login");
  const backup = await ctx.rawRequest({ actor: "backup-login", path: "/api/auth/passkey/verify-authentication", method: "POST", json: { response: key.authenticate(backupOptions, "https://passkeys.example", 2, 0x19, options.user.id) } });
  expect(backup.status).toBe(200); f.observations.push(backup);
  const backupTrace = asArray((await f.trace()).events).map(asRecord);
  expect(backupTrace[0]).toMatchObject({ info: { newCounter: 2, credentialDeviceType: "multiDevice", credentialBackedUp: true } });
  await f.control();
  const invalidBackupOptions = await f.authenticationOptions("invalid-backup");
  const invalidBackup = await ctx.rawRequest({ actor: "invalid-backup", path: "/api/auth/passkey/verify-authentication", method: "POST", json: { response: key.authenticate(invalidBackupOptions, "https://passkeys.example", 3, 0x11, options.user.id) } });
  expect(invalidBackup.status).toBe(400); f.observations.push(invalidBackup);
  expect((await f.trace()).events).toEqual([]);
  const stored = await ctx.rawRequest({ path: "/api/auth/passkey/list-user-passkeys" });
  expect(asRecord(asArray(stored.body)[0])).toMatchObject({ counter: 2, deviceType: "singleDevice", backedUp: false });
  f.observations.push(stored);

  await f.control({ noExtensions: true });
  expect(asRecord(await f.options()).extensions).toEqual({ credProps: true });
  const cookieResponse = await ctx.actor().fetch(`${ctx.baseURL}/api/auth/passkey/generate-register-options`);
  expect(cookieResponse.headers.get("set-cookie")).toContain("better-auth.ceremony=");
  expect(cookieResponse.headers.get("set-cookie")).not.toContain("better-auth-passkey=");
  return f.observations;
});

compatScenario("Passkey callback failures consume the challenge before writing credentials or counters", async (ctx) => {
  await signUpUser(ctx, "primary", "passkey-callback-errors", "Owner");
  const f = fixture(ctx); const key = authenticator("passkey-callback-error-key");
  const options = await f.options();
  expect((await f.register(key, options)).status).toBe(200);
  for (const mode of ["api-error", "error"]) {
    await f.control({ authenticationMode: mode });
    const options = await f.authenticationOptions();
    const response = key.authenticate(options, "https://secondary.example", 1, 0x01, "");
    const failed = await ctx.rawRequest({ actor: "login", path: "/api/auth/passkey/verify-authentication", method: "POST", json: { response } });
    expect(failed.status).toBe(mode === "api-error" ? 403 : 400); f.observations.push(failed);
    expect(asRecord(failed.body).code).toBe(mode === "api-error" ? "PASSKEY_CALLBACK_REJECTED" : "AUTHENTICATION_FAILED");
    const retry = await ctx.rawRequest({ actor: "login", path: "/api/auth/passkey/verify-authentication", method: "POST", json: { response } });
    expect(asRecord(retry.body).code).toBe("CHALLENGE_NOT_FOUND"); f.observations.push(retry);
    const listed = await ctx.rawRequest({ path: "/api/auth/passkey/list-user-passkeys" });
    expect(asRecord(asArray(listed.body)[0]).counter).toBe(0); f.observations.push(listed);
    expect(asArray((await f.trace()).events).map(asRecord).map((event) => event.event)).toEqual(["authentication.verified"]);

    await f.control({ registrationMode: mode });
    const registerOptions = await f.options();
    const registered = await f.register(authenticator(`rejected-${mode}`), registerOptions);
    expect(registered.status).toBe(mode === "api-error" ? 403 : 500);
    expect(asRecord(registered.body).code).toBe(mode === "api-error" ? "PASSKEY_CALLBACK_REJECTED" : "FAILED_TO_VERIFY_REGISTRATION");
  }
  await f.control({ registrationMode: "allow", targetUserId: "another-user" });
  const mismatch = await f.register(authenticator("wrong-target"), await f.options());
  expect(mismatch.status).toBe(401);
  expect(asRecord(mismatch.body).code).toBe("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY");
  await f.trace();
  return f.observations;
});

compatScenario("Passkey route schemas reject invalid input before callbacks and require a registration response", async (ctx) => {
  await signUpUser(ctx, "primary", "passkey-schema", "Owner");
  const f = fixture(ctx); await f.control();
  const results = [];
  for (const [path, json, message] of [
    ["verify-registration", { name: null }, "[body.response] Invalid input: expected nonoptional, received undefined; [body.name] Invalid input: expected string, received null"],
    ["verify-registration", { response: null, createSession: null }, "[body.createSession] Invalid input: expected boolean, received null"],
    ["verify-registration", { response: null, createSession: "true" }, "[body.createSession] Invalid input: expected boolean, received string"],
    ["verify-authentication", { response: null }, "[body.response] Invalid input: expected record, received null"],
    ["verify-authentication", {}, "[body.response] Invalid input: expected record, received undefined"],
  ] as const) {
    const result = await ctx.rawRequest({ path: `/api/auth/passkey/${path}`, method: "POST", json });
    expect(result.status).toBe(400); expect(asRecord(result.body)).toEqual({ code: "VALIDATION_ERROR", message }); results.push(result);
  }
  const missing = await ctx.rawRequest({ path: "/api/auth/passkey/verify-registration", method: "POST", json: {} });
  expect(missing.status).toBe(400); expect(asRecord(missing.body)).toEqual({ code: "VALIDATION_ERROR", message: "[body.response] Invalid input: expected nonoptional, received undefined" }); results.push(missing);
  const nullable = await ctx.rawRequest({ path: "/api/auth/passkey/verify-registration", method: "POST", json: { response: null } });
  expect(nullable.status).toBe(400); expect(asRecord(nullable.body).code).toBe("CHALLENGE_NOT_FOUND"); results.push(nullable);
  const query = await ctx.rawRequest({ path: "/api/auth/passkey/generate-register-options?authenticatorAttachment=invalid" });
  expect(query.status).toBe(400); results.push(query);
  expect((await f.trace()).events).toEqual([]);
  return { results, observations: f.observations };
});
