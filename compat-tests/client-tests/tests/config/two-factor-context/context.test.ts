import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("two-factor sender receives validated endpoint context and preserves delivery-error semantics", async (ctx) => {
  const client = ctx.actor().client;
  const email = ctx.uniqueEmail("two-factor-context");
  const signup = await client.signUp.email({ email, name: "Context User", password: "password123" });
  expect(signup.error).toBeNull();
  const post = (route: string, json: unknown, headers?: HeadersInit, actor?: string) => ctx.rawRequest({ actor, path: `/api/auth/two-factor/${route}`, method: "POST", json, headers });
  const enabled = await post("enable", { password: "password123", method: "otp" });
  expect(enabled.status).toBe(200);
  await client.signOut();
  const challenge = await client.signIn.email({ email, password: "password123" });
  expect(challenge.data).toEqual({ twoFactorRedirect: true, twoFactorMethods: ["otp"] });
  const invalid = await post("send-otp", { trustDevice: "yes" });
  expect(invalid.status).toBe(400);
  expect(invalid.body).toMatchObject({ code: "VALIDATION_ERROR" });
  const anonymous = await post("send-otp", {}, undefined, "anonymous");
  expect(anonymous.status).toBe(401);
  const sent = await post("send-otp", { trustDevice: true, unknown: "filtered" }, { "x-callback-tag": "pending" });
  expect(sent.status).toBe(200);
  const first = await ctx.readTwoFactorOtp({ email }) as { otp: string };
  const verified = await post("verify-otp", { code: first.otp });
  expect(verified.status).toBe(200);
  expect((verified.body as { user: Record<string, unknown> }).user.secretNote).toBeUndefined();
  const failedDelivery = await post("send-otp", { trustDevice: false, unknown: "filtered" }, { "x-callback-tag": "session", "x-callback-fail": "send" });
  expect(failedDelivery.status).toBe(200);
  expect(failedDelivery.body).toEqual({ status: true });
  const next = await ctx.readTwoFactorOtp({ email }) as { otp: string };
  const afterFailure = await post("verify-otp", { code: next.otp });
  expect(afterFailure.status).toBe(200);
  expect((afterFailure.body as { user: Record<string, unknown> }).user.secretNote).toBeUndefined();
  const events = await fetch(`${ctx.baseURL}/__test/two-factor-context`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).then((response) => response.json());
  expect(events).toEqual([
    { user: { id: signup.data!.user.id, email, secretNote: "hidden" }, databaseUser: { id: signup.data!.user.id, email }, path: "/two-factor/send-otp", requestPath: "/two-factor/send-otp", body: { trustDevice: true }, header: "pending", sessionEmail: null, hasResponse: false, otpLength: 8 },
    { user: { id: signup.data!.user.id, email, secretNote: null }, databaseUser: { id: signup.data!.user.id, email }, path: "/two-factor/send-otp", requestPath: "/two-factor/send-otp", body: { trustDevice: false }, header: "session", sessionEmail: email, hasResponse: false, otpLength: 8 },
  ]);
  const totp = await post("enable", { password: "password123" });
  expect(totp.status).toBe(200);
  await client.signOut();
  expect((await client.signIn.email({ email, password: "password123" })).error).toBeNull();
  const backup = await post("verify-backup-code", { code: (totp.body as { backupCodes: string[] }).backupCodes[0], disableSession: true });
  expect(backup.status).toBe(200);
  const backupUser = (backup.body as { user: Record<string, unknown> }).user;
  expect(backupUser.id).toBe(signup.data!.user.id);
  expect(backupUser.secretNote).toBeUndefined();
  return { invalid, anonymous, sent, verified, failedDelivery, afterFailure, backup, events };
});
