import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const callback = () => {};
const cases = {
  omitted: {},
  explicitDefaults: { logger: { disabled: false, level: "warn" }, session: { cookieCache: { enabled: false, maxAge: 300, strategy: "compact" } }, advanced: { disableCSRFCheck: false, useSecureCookies: false, database: { defaultFindManyLimit: 100 }, defaultCookieAttributes: { secure: false, httpOnly: true, sameSite: "lax", path: "/" } }, rateLimit: { storage: "memory" } },
  explicitValues: { logger: { disabled: true, level: "error", log: callback }, session: { cookieCache: { enabled: true, maxAge: 900, strategy: "jwe" }, freshAge: 0 }, advanced: { cookiePrefix: "", useSecureCookies: true, disableCSRFCheck: true, database: { defaultFindManyLimit: 0 }, defaultCookieAttributes: { secure: true, httpOnly: false, sameSite: "none", domain: "example.test", path: "/auth" } }, onAPIError: { errorURL: "https://example.test/error", onError: callback }, rateLimit: { storage: "secondary-storage", customStorage: {} } },
  callbacks: { emailAndPassword: { enabled: true, disableSignUp: true, requireEmailVerification: true, sendResetPassword: callback, onPasswordReset: callback, revokeSessionsOnPasswordReset: true, password: { hash: callback, verify: callback } }, emailVerification: { sendVerificationEmail: callback, sendOnSignUp: true, sendOnSignIn: true, autoSignInAfterVerification: true, beforeEmailVerification: callback, afterEmailVerification: callback }, user: { changeEmail: { sendChangeEmailConfirmation: callback } } },
  databaseHooks: { databaseHooks: { user: { create: { before: callback }, update: { after: callback }, delete: { before: callback } }, session: { create: { after: callback } }, account: { update: { before: callback } }, verification: { create: { after: callback } } } },
};
cases.pluginOmitted = { emailAndPassword: { enabled: true }, emailVerification: {}, user: { changeEmail: {} } };
cases.pluginDefaults = { emailAndPassword: { enabled: true, minPasswordLength: 8, maxPasswordLength: 128, autoSignIn: true, resetPasswordTokenExpiresIn: 3600 }, emailVerification: { expiresIn: 3600 }, user: { changeEmail: { enabled: false } } };
cases.pluginValues = { emailAndPassword: { enabled: true, minPasswordLength: 12, maxPasswordLength: 24, autoSignIn: false, resetPasswordTokenExpiresIn: 0 }, emailVerification: { expiresIn: 90 }, user: { changeEmail: { enabled: true } } };
cases.fractionalDurations = { session: { expiresIn: 12.25, updateAge: 0.5, freshAge: -0.125, cookieCache: { maxAge: 0.000000001 } } };
Object.assign(cases.explicitDefaults.session, { expiresIn: 604800, updateAge: 86400, disableSessionRefresh: false, storeSessionInDatabase: false, preserveSessionInDatabase: false });
cases.explicitDefaults.account = { encryptOAuthTokens: false, updateAccountOnSignIn: true, accountLinking: { enabled: true, allowUnlinkingAll: false, updateUserInfoOnLink: false } };
cases.explicitDefaults.verification = { disableCleanup: false };
cases.explicitDefaults.onAPIError = { throw: false };
Object.assign(cases.explicitValues.session, { expiresIn: 30, updateAge: 0, disableSessionRefresh: true, storeSessionInDatabase: true, preserveSessionInDatabase: true });
cases.explicitValues.account = { encryptOAuthTokens: true, updateAccountOnSignIn: false, accountLinking: { enabled: false, allowUnlinkingAll: true, updateUserInfoOnLink: true } };
cases.explicitValues.verification = { disableCleanup: true };
cases.explicitValues.onAPIError.throw = true;
Object.assign(cases.explicitDefaults.rateLimit, { enabled: false, window: 10, max: 100 });
Object.assign(cases.explicitValues.rateLimit, { enabled: true, window: 0, max: 0 });
cases.idDatabase = { advanced: { database: { generateId: false } } };
cases.idSerial = { advanced: { database: { generateId: "serial" } } };
cases.idUuid = { advanced: { database: { generateId: "uuid" } } };
cases.idCustom = { advanced: { database: { generateId: () => { throw new Error("telemetry must not call generateId"); } } } };
export const fixturePath = new URL("../../../tests/fixtures/telemetry-options-1.7.6.json", import.meta.url);

export async function collectTelemetryOptions(modulePath) {
  const moduleSpecifier = modulePath ? pathToFileURL(modulePath).href : "@better-auth/telemetry";
  const { getTelemetryAuthConfig } = await import(moduleSpecifier);
  const results = {};
  for (const [name, options] of Object.entries(cases)) {
    results[name] = JSON.parse(JSON.stringify(await getTelemetryAuthConfig(options)));
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const results = await collectTelemetryOptions(process.env.TELEMETRY_REFERENCE_MODULE);
  if (process.env.TELEMETRY_REFERENCE_OUTPUT) {
    writeFileSync(process.env.TELEMETRY_REFERENCE_OUTPUT, JSON.stringify(results, null, 2) + "\n");
    console.log(`Wrote ${Object.keys(results).length} telemetry option projection cases from the pinned upstream module`);
  } else {
    assert.deepEqual(results, JSON.parse(readFileSync(fixturePath, "utf8")));
    console.log(`${Object.keys(results).length} telemetry option projection cases match the Rust fixture`);
  }
}
