import { createAuthClient } from "better-auth/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { compatScenario } from "../../support/scenario";

function twoFactorActor(
  ctx: Parameters<Parameters<typeof compatScenario>[1]>[0],
  name = "primary",
) {
  const actor = ctx.actor(name);
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [twoFactorClient()],
    fetchOptions: {
      customFetchImpl: actor.fetch,
    },
  });
}

function redactBackupCodePayload<T>(value: T): T {
  if (!value || typeof value !== "object") {
    return value;
  }

  const clone = structuredClone(value as object) as Record<string, unknown>;
  if (
    clone.data &&
    typeof clone.data === "object" &&
    !Array.isArray(clone.data)
  ) {
    const data = clone.data as Record<string, unknown>;
    if (Array.isArray(data.backupCodes)) {
      data.backupCodes = data.backupCodes.map(() => "<backup-code>");
    }
    if (typeof data.totpURI === "string") {
      data.totpURI = "<totpURI>";
    }
  }
  return clone as T;
}

function redactRawBackupCodeResponse<T>(value: T): T {
  if (!value || typeof value !== "object") {
    return value;
  }

  const clone = structuredClone(value as object) as Record<string, unknown>;
  if (
    clone.body &&
    typeof clone.body === "object" &&
    !Array.isArray(clone.body)
  ) {
    const body = clone.body as Record<string, unknown>;
    if (Array.isArray(body.backupCodes)) {
      body.backupCodes = body.backupCodes.map(() => "<backup-code>");
    }
  }

  return clone as T;
}

function decodeBase32(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = secret.toUpperCase().replace(/=+$/g, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of normalized) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) {
      continue;
    }
    value = (value << 5) | idx;
    bits += 5;
    while (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

async function generateCurrentTotp(totpURI: string) {
  const url = new URL(totpURI);
  const secret = url.searchParams.get("secret");
  if (!secret) {
    throw new Error("TOTP URI is missing the secret");
  }

  const digits = Number(url.searchParams.get("digits") ?? "6");
  const period = Number(url.searchParams.get("period") ?? "30");
  const counter = Math.floor(Date.now() / 1000 / period);

  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(4, counter);

  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, counterBytes),
  );
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = ((digest[offset]! & 0x7f) << 24)
    | (digest[offset + 1]! << 16)
    | (digest[offset + 2]! << 8)
    | digest[offset + 3]!;

  return String(binary % 10 ** digits).padStart(digits, "0");
}

compatScenario("two-factor generate-backup-codes replaces the backup code set for enabled users", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase12-generate");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 12 Generate",
  });

  const enable = await client.twoFactor.enable({ password });
  const setupCode = await generateCurrentTotp(enable.data!.totpURI);
  await client.twoFactor.verifyTotp({ code: setupCode });

  const generateBackupCodes = await client.twoFactor.generateBackupCodes({ password });

  return {
    generateBackupCodes: ctx.snapshot(redactBackupCodePayload(generateBackupCodes)),
  };
});

compatScenario("two-factor verify-backup-code signs the user in and consumes the used code", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase12-verify");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 12 Verify",
  });

  const enable = await client.twoFactor.enable({ password });
  const setupCode = await generateCurrentTotp(enable.data!.totpURI);
  await client.twoFactor.verifyTotp({ code: setupCode });

  const generated = await client.twoFactor.generateBackupCodes({ password });
  const backupCode = generated.data!.backupCodes[0]!;

  await client.signOut();

  const signIn = await client.signIn.email({
    email,
    password,
  });
  const verifyBackupCode = await client.twoFactor.verifyBackupCode({ code: backupCode });
  const session = await client.getSession();

  await client.signOut();
  await client.signIn.email({
    email,
    password,
  });
  const reusedBackupCode = await client.twoFactor.verifyBackupCode({ code: backupCode });

  return {
    signIn: ctx.snapshot(signIn),
    verifyBackupCode: ctx.snapshot(verifyBackupCode),
    session: ctx.snapshot(session),
    reusedBackupCode: ctx.snapshot(reusedBackupCode),
  };
});

compatScenario("two-factor server-only backup code retrieval returns parsed arrays", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase12-view");
  const password = "password123";

  const signup = await client.signUp.email({
    email,
    password,
    name: "Phase 12 View",
  });

  const enable = await client.twoFactor.enable({ password });
  const setupCode = await generateCurrentTotp(enable.data!.totpURI);
  await client.twoFactor.verifyTotp({ code: setupCode });
  const generated = await client.twoFactor.generateBackupCodes({ password });

  const viewBackupCodes = await ctx.rawRequest({
    path: `/__test/view-backup-codes?userId=${encodeURIComponent(signup.data!.user.id)}`,
  });

  return {
    generated: ctx.snapshot(redactBackupCodePayload(generated)),
    viewBackupCodes: ctx.snapshot(redactRawBackupCodeResponse(viewBackupCodes)),
  };
});

compatScenario("two-factor view-backup-codes stays unexposed as a public HTTP route", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase12-no-route");
  const password = "password123";

  const signup = await client.signUp.email({
    email,
    password,
    name: "Phase 12 No Route",
  });

  const enable = await client.twoFactor.enable({ password });
  const setupCode = await generateCurrentTotp(enable.data!.totpURI);
  await client.twoFactor.verifyTotp({ code: setupCode });

  const publicRoute = await ctx.rawRequest({
    path: "/api/auth/two-factor/view-backup-codes",
    method: "POST",
    json: {
      userId: signup.data!.user.id,
    },
  });

  return {
    publicRoute: ctx.snapshot(publicRoute),
  };
});
