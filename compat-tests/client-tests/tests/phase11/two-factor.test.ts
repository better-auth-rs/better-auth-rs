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

function redactTwoFactorPayload<T>(value: T): T {
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
    if (typeof data.totpURI === "string") {
      data.totpURI = "<totpURI>";
    }
    if (Array.isArray(data.backupCodes)) {
      data.backupCodes = data.backupCodes.map(() => "<backup-code>");
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

compatScenario("two-factor enrollment returns URIs and keeps the user disabled until verification", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-enable");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 11 Enrollment",
  });

  const enable = await client.twoFactor.enable({ password });
  const totp = await client.twoFactor.getTotpUri({ password });
  const session = await client.getSession();

  return {
    enable: ctx.snapshot(redactTwoFactorPayload(enable)),
    totp: ctx.snapshot(redactTwoFactorPayload(totp)),
    session: ctx.snapshot(session),
  };
});

compatScenario("two-factor totp verification enables the user and later sign-in redirects to second factor", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-totp");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 11 TOTP",
  });

  const enable = await client.twoFactor.enable({ password });
  const code = await generateCurrentTotp(enable.data!.totpURI);
  const verifyTotp = await client.twoFactor.verifyTotp({ code });
  const session = await client.getSession();

  await client.signOut();
  const signIn = await client.signIn.email({
    email,
    password,
    rememberMe: false,
  });

  return {
    verifyTotp: ctx.snapshot(verifyTotp),
    session: ctx.snapshot(session),
    signIn: ctx.snapshot(signIn),
  };
});

compatScenario("two-factor otp flow completes sign-in and rejects requests without the pending cookie", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-otp");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 11 OTP",
  });

  const enable = await client.twoFactor.enable({ password });
  const setupCode = await generateCurrentTotp(enable.data!.totpURI);
  await client.twoFactor.verifyTotp({ code: setupCode });
  await client.signOut();

  const signIn = await client.signIn.email({
    email,
    password,
    rememberMe: false,
  });
  const sendOtp = await client.twoFactor.sendOtp({});
  const otpRecord = await ctx.readTwoFactorOtp({ email }) as { otp: string };
  const verifyOtp = await client.twoFactor.verifyOtp({ code: otpRecord.otp });
  const session = await client.getSession();

  const missingCookieClient = twoFactorActor(ctx, "missing-cookie");
  const missingCookie = await missingCookieClient.twoFactor.verifyOtp({
    code: otpRecord.otp,
  });

  return {
    signIn: ctx.snapshot(signIn),
    sendOtp: ctx.snapshot(sendOtp),
    verifyOtp: ctx.snapshot(verifyOtp),
    session: ctx.snapshot(session),
    missingCookie: ctx.snapshot(missingCookie),
  };
});

compatScenario("two-factor trusted devices bypass the second-factor challenge on later sign-ins", async (ctx) => {
  const client = twoFactorActor(ctx);
  const email = ctx.uniqueEmail("phase11-trust");
  const password = "password123";

  await client.signUp.email({
    email,
    password,
    name: "Phase 11 Trust Device",
  });

  const enable = await client.twoFactor.enable({ password });
  const setupCode = await generateCurrentTotp(enable.data!.totpURI);
  await client.twoFactor.verifyTotp({ code: setupCode });
  await client.signOut();

  const signIn = await client.signIn.email({
    email,
    password,
  });
  await client.twoFactor.sendOtp({});
  const otpRecord = await ctx.readTwoFactorOtp({ email }) as { otp: string };
  const verifyOtp = await client.twoFactor.verifyOtp({
    code: otpRecord.otp,
    trustDevice: true,
  });

  await client.signOut();
  const trustedSignIn = await client.signIn.email({
    email,
    password,
  });

  return {
    signIn: ctx.snapshot(signIn),
    verifyOtp: ctx.snapshot(verifyOtp),
    trustedSignIn: ctx.snapshot(trustedSignIn),
  };
});
