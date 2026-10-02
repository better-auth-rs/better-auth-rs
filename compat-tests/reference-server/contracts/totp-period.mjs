import { writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { twoFactor } from "better-auth/plugins";
import { createOTP } from "@better-auth/utils/otp";

export const secret = "ordinary-totp-period-fixture";
export const issuer = "Ordinary TOTP";
export const account = "ordinary@totp-period.test";

const times = [1_700_000_025_125, 1_700_000_002_625];

export const caseInputs = [
  { name: "omitted", options: {} },
  { name: "fractional", options: { period: 30.5 } },
].flatMap(({ name, options }) => [6, 8].flatMap((digits) =>
  times.map((timestampMillis, index) => ({
    name: `${name}-digits-${digits}-time-${index + 1}`,
    options: { ...options, digits },
    timestampMillis,
  })),
));

export async function capture(input) {
  const auth = betterAuth({
    baseURL: "http://totp-period.test",
    secret: "ordinary-totp-period-server-secret-longer-than-32-characters",
    database: memoryAdapter({ user: [], session: [], account: [], verification: [], twoFactor: [] }),
    logger: { disabled: true },
    telemetry: { enabled: false },
    rateLimit: { enabled: false },
    plugins: [twoFactor({ totpOptions: input.options })],
  });
  await auth.$context;
  const otp = createOTP(secret, input.options);
  const originalNow = Date.now;
  try {
    Date.now = () => input.timestampMillis;
    return {
      ...input,
      server: await auth.api.generateTOTP({ body: { secret } }),
      helper: { code: await otp.totp(), uri: otp.url(issuer, account) },
    };
  } finally {
    Date.now = originalNow;
  }
}

if (import.meta.main) {
  const cases = [];
  for (const input of caseInputs) cases.push(await capture(input));
  const result = JSON.stringify({ version: "1.7.6", secret, issuer, account, cases }, null, 2) + "\n";
  if (process.env.TOTP_PERIOD_OUTPUT) writeFileSync(process.env.TOTP_PERIOD_OUTPUT, result);
  else process.stdout.write(result);
}
