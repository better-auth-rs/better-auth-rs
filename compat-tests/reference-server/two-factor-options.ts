import type { Database } from "bun:sqlite";
import type { twoFactor } from "better-auth/plugins";
import { APIError } from "better-auth/api";

const cipher = {
  encrypt: async (value: string) => `fixture-${[...value].reverse().join("")}`,
  decrypt: async (value: string) => {
    if (!value.startsWith("fixture-")) throw new Error("Invalid fixture ciphertext");
    return [...value.slice(8)].reverse().join("");
  },
};

export function twoFactorOptions(profile: string): NonNullable<Parameters<typeof twoFactor>[0]> {
  if (!profile.startsWith("two-factor-")) return {};
  const config: NonNullable<Parameters<typeof twoFactor>[0]> = {
    allowPasswordless: true,
    skipVerificationOnEnable: true,
    issuer: "Enrollment Issuer",
    totpOptions: { digits: 8, period: 60 },
    otpOptions: { digits: 8, period: 2, allowedAttempts: 2 },
    backupCodeOptions: { amount: 3, length: 6 },
  };
  switch (profile) {
    case "two-factor-plain": config.backupCodeOptions!.storeBackupCodes = "plain"; break;
    case "two-factor-hashed": config.otpOptions!.storeOTP = "hashed"; break;
    case "two-factor-encrypted": config.otpOptions!.storeOTP = "encrypted"; break;
    case "two-factor-custom":
      config.otpOptions!.storeOTP = { hash: async (code) => {
        if (code === "codec-error") throw new APIError("SERVICE_UNAVAILABLE", { code: "CODEC_UNAVAILABLE", message: "Fixture codec unavailable" });
        return `fixture-${code}`;
      } };
      config.backupCodeOptions!.storeBackupCodes = cipher;
      config.backupCodeOptions!.customBackupCodesGenerate = () => ["duplicate-code", "duplicate-code", "last-code"];
      break;
    case "two-factor-custom-encrypted": config.otpOptions!.storeOTP = cipher; break;
    case "two-factor-disabled": config.totpOptions!.disable = true; break;
    case "two-factor-password-policy":
      config.totpOptions!.allowPasswordless = false;
      config.backupCodeOptions!.allowPasswordless = false;
      break;
  }
  return config;
}

export function twoFactorOptionsState(database: Database, userId: string) {
  return {
    factor: database.query('SELECT secret, backupCodes, verified FROM twoFactor WHERE userId = ?').get(userId) ?? null,
    otp: database.query("SELECT value, expiresAt, createdAt FROM verification WHERE identifier LIKE '2fa-otp-%' ORDER BY createdAt DESC LIMIT 1").get() ?? null,
  };
}
