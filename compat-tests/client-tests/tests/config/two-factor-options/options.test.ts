import { expect } from "bun:test";
import { symmetricDecrypt } from "better-auth/crypto";
import { compatScenario } from "../../../support/scenario";

const profile = process.env.COMPAT_PROFILE;
if (!profile) throw new Error("COMPAT_PROFILE is required for the two-factor options suite");
const secret = "compat-test-only-key-not-real-minimum-32chars";
type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
const post = (ctx: Context, path: string, json: unknown) => ctx.rawRequest({ path: `/api/auth/two-factor/${path}`, method: "POST", json });

async function signup(ctx: Context, suffix: string) {
  const email = ctx.uniqueEmail(suffix);
  const result = await ctx.actor().client.signUp.email({ email, password: "password123", name: "Factor Options" });
  expect(result.error).toBeNull();
  return { email, id: result.data!.user.id };
}

async function state(ctx: Context, userId: string) {
  const response = await fetch(`${ctx.baseURL}/__test/two-factor-options?userId=${userId}`);
  expect(response.status).toBe(200);
  return await response.json() as {
    factor: { secret: string; backupCodes: string; verified: boolean | number } | null;
    otp: { value: string; expiresAt: string | number; createdAt: string | number } | null;
  };
}

async function decodeBackupCodes(value: string): Promise<string[]> {
  if (profile === "two-factor-plain") return JSON.parse(value);
  if (profile === "two-factor-custom") {
    expect(value.startsWith("fixture-")).toBe(true);
    return JSON.parse([...value.slice(8)].reverse().join(""));
  }
  return JSON.parse(await symmetricDecrypt({ key: secret, data: value }));
}

compatScenario("two-factor options preserve password policy and factor disabling", async (ctx) => {
  const user = await signup(ctx, "factor-policy");
  const missing = await post(ctx, "enable", {});
  expect(missing.status).toBe(400);
  expect(missing.body).toMatchObject({ code: "INVALID_PASSWORD" });
  const invalid = await post(ctx, "enable", { password: null, method: "unknown", issuer: 4 });
  expect(invalid.status).toBe(400);
  expect(invalid.body).toMatchObject({ code: "VALIDATION_ERROR" });
  const long = await post(ctx, "enable", { password: "x".repeat(129) });
  expect(long.status).toBe(400);
  expect(long.body).toMatchObject({ code: "PASSWORD_TOO_LONG" });
  await ctx.removeCredentialAccount({ email: user.email });
  const enabled = await post(ctx, "enable", {});
  if (profile === "two-factor-disabled") {
    expect(enabled.status).toBe(400);
    expect(enabled.body).toMatchObject({ code: "TOTP_NOT_CONFIGURED" });
    const uri = await post(ctx, "get-totp-uri", {});
    const verify = await post(ctx, "verify-totp", { code: "12345678" });
    expect(uri.body).toMatchObject({ code: "TOTP_NOT_CONFIGURED" });
    expect(verify.body).toMatchObject({ code: "TOTP_NOT_CONFIGURED" });
    expect((await state(ctx, user.id)).factor).toBeNull();
    return { missing, invalid, long, enabled, uri, verify };
  }
  expect(enabled.status).toBe(200);
  const uri = await post(ctx, "get-totp-uri", {});
  const regenerated = await post(ctx, "generate-backup-codes", {});
  if (profile === "two-factor-password-policy") {
    expect(uri.status).toBe(400);
    expect(regenerated.status).toBe(400);
    expect(uri.body).toMatchObject({ code: "VALIDATION_ERROR" });
    expect(regenerated.body).toMatchObject({ code: "VALIDATION_ERROR" });
    const wrong = await post(ctx, "get-totp-uri", { password: "password123" });
    expect(wrong.body).toMatchObject({ code: "INVALID_PASSWORD" });
  } else {
    expect(uri.status).toBe(200);
    expect(regenerated.status).toBe(200);
  }
  const disabled = await post(ctx, "disable", {});
  expect(disabled.status).toBe(200);
  expect((await state(ctx, user.id)).factor).toBeNull();
  return { missing, invalid, long, uriStatus: uri.status, regenerationStatus: regenerated.status, disabled };
});

if (profile !== "two-factor-disabled") compatScenario("configured backup codecs and TOTP parameters survive persistence and single use", async (ctx) => {
  const user = await signup(ctx, "factor-storage");
  const enabled = await post(ctx, "enable", { password: "password123" });
  expect(enabled.status).toBe(200);
  const body = enabled.body as { method: string; totpURI: string; backupCodes: string[] };
  expect(body.method).toBe("totp");
  const uri = new URL(body.totpURI);
  expect(uri.searchParams.get("digits")).toBe("8");
  expect(uri.searchParams.get("period")).toBe("60");
  expect(uri.searchParams.get("issuer")).toBe("Enrollment Issuer");
  expect(body.backupCodes).toHaveLength(3);
  if (profile !== "two-factor-custom") for (const code of body.backupCodes) expect(code).toMatch(/^[a-zA-Z0-9]{5}-[a-zA-Z0-9]$/);
  const stored = await state(ctx, user.id);
  expect(Boolean(stored.factor!.verified)).toBe(true);
  expect(await decodeBackupCodes(stored.factor!.backupCodes)).toEqual(body.backupCodes);
  const decodedSecret = await symmetricDecrypt({ key: secret, data: stored.factor!.secret });
  expect(decodedSecret).toHaveLength(32);
  const generated = await fetch(`${ctx.baseURL}/__test/generate-totp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ secret: decodedSecret }) });
  expect(generated.status).toBe(200);
  const { code } = await generated.json() as { code: string };
  expect(code).toMatch(/^\d{8}$/);
  const verified = await post(ctx, "verify-totp", { code });
  expect(verified.status).toBe(200);
  const readUri = await post(ctx, "get-totp-uri", { password: "password123" });
  expect(readUri.status).toBe(200);
  const readIssuer = new URL((readUri.body as { totpURI: string }).totpURI).searchParams.get("issuer");
  expect(readIssuer).not.toBe("Enrollment Issuer");
  const view = await fetch(`${ctx.baseURL}/__test/view-backup-codes?userId=${user.id}`).then((response) => response.json());
  expect(view).toEqual({ status: true, backupCodes: body.backupCodes });
  const used = await post(ctx, "verify-backup-code", { code: body.backupCodes[0], disableSession: true });
  expect(used.status).toBe(200);
  const remaining = await decodeBackupCodes((await state(ctx, user.id)).factor!.backupCodes);
  expect(remaining).toEqual(body.backupCodes.filter((code) => code !== body.backupCodes[0]));
  const replay = await post(ctx, "verify-backup-code", { code: body.backupCodes[0], disableSession: true });
  expect(replay.status).toBe(401);
  expect(replay.body).toMatchObject({ code: "INVALID_BACKUP_CODE" });
  return { verified, used, replay, readIssuer, remainingCount: remaining.length, digits: 8, period: 60 };
});

compatScenario("configured OTP codecs preserve attempt budget and one-time consumption", async (ctx) => {
  const user = await signup(ctx, "factor-otp-options");
  expect((await post(ctx, "enable", { password: "password123", method: "otp" })).status).toBe(200);
  await ctx.actor().client.signOut();
  const challenge = await ctx.actor().client.signIn.email({ email: user.email, password: "password123" });
  expect(challenge.data).toEqual({ twoFactorRedirect: true, twoFactorMethods: ["otp"] });
  expect((await post(ctx, "send-otp", {})).status).toBe(200);
  const { otp } = await ctx.readTwoFactorOtp({ email: user.email }) as { otp: string };
  expect(otp).toMatch(/^\d{8}$/);
  const stored = (await state(ctx, user.id)).otp!;
  const lifetime = (new Date(stored.expiresAt).getTime() - new Date(stored.createdAt).getTime()) / 1000;
  expect(lifetime).toBeGreaterThan(118);
  expect(lifetime).toBeLessThanOrEqual(120);
  expect(stored.value.endsWith(":0")).toBe(true);
  const encoded = stored.value.slice(0, -2);
  if (profile === "two-factor-hashed") {
    const expected = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(otp))).toString("base64url");
    expect(encoded).toBe(expected);
  } else if (profile === "two-factor-encrypted") {
    expect(await symmetricDecrypt({ key: secret, data: encoded })).toBe(otp);
  } else if (profile === "two-factor-custom") expect(encoded).toBe(`fixture-${otp}`);
  else if (profile === "two-factor-custom-encrypted") expect(encoded).toBe(`fixture-${[...otp].reverse().join("")}`);
  else expect(encoded).toBe(otp);
  let codecError = null;
  if (profile === "two-factor-custom") {
    codecError = await post(ctx, "verify-otp", { code: "codec-error" });
    expect(codecError.status).toBe(503);
    expect(codecError.body).toEqual({ code: "CODEC_UNAVAILABLE", message: "Fixture codec unavailable" });
    const consumed = await post(ctx, "verify-otp", { code: otp });
    expect(consumed.body).toMatchObject({ code: "OTP_HAS_EXPIRED" });
    expect((await post(ctx, "send-otp", {})).status).toBe(200);
  }
  const failures = [];
  for (let attempt = 0; attempt < 2; attempt++) {
    const failure = await post(ctx, "verify-otp", { code: "invalid" });
    expect(failure.status).toBe(401);
    expect(failure.body).toMatchObject({ code: "INVALID_CODE" });
    failures.push(failure);
  }
  const exhausted = await post(ctx, "verify-otp", { code: otp });
  expect(exhausted.body).toMatchObject({ code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE" });
  const expired = await post(ctx, "verify-otp", { code: otp });
  expect(expired.body).toMatchObject({ code: "OTP_HAS_EXPIRED" });
  expect((await post(ctx, "send-otp", {})).status).toBe(200);
  const next = await ctx.readTwoFactorOtp({ email: user.email }) as { otp: string };
  const verified = await post(ctx, "verify-otp", { code: next.otp });
  expect(verified.status).toBe(200);
  const replay = await post(ctx, "verify-otp", { code: next.otp });
  expect(replay.body).toMatchObject({ code: "OTP_HAS_EXPIRED" });
  return { codecError, failures, exhausted, expired, verified, replay };
});
