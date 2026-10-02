import { Database } from "bun:sqlite";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { phoneNumber } = await import(`${modules}/better-auth/dist/plugins/phone-number/index.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);

const phone = "+15551230001";
const now = 1_700_000_000_123;
const paths = {
  send: "/phone-number/send-otp",
  signIn: "/sign-in/phone-number",
  reset: "/phone-number/request-password-reset",
};

export async function capture(name, seconds, operation) {
  const database = new Database(":memory:");
  const sent = [];
  const options = {
    database,
    baseURL: "http://phone-duration.test",
    secret: "ordinary-phone-duration-secret-longer-than-32-characters",
    telemetry: { enabled: false },
    logger: { disabled: true },
    rateLimit: { enabled: false },
    plugins: [phoneNumber({
      ...(name === "omitted" ? {} : { expiresIn: seconds }),
      requireVerification: true,
      sendOTP(data) { sent.push({ kind: "verification", ...data }); },
      sendPasswordResetOTP(data) { sent.push({ kind: "reset", ...data }); },
    })],
  };
  try {
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const context = await auth.$context;
    await context.adapter.create({ model: "user", forceAllowId: true, data: {
      id: "ordinary-user", name: "Phone Duration", email: "ordinary@phone-duration.test",
      emailVerified: false, phoneNumber: phone, phoneNumberVerified: false,
      createdAt: new Date(now), updatedAt: new Date(now),
    } });
    await context.adapter.create({ model: "account", forceAllowId: true, data: {
      id: "ordinary-credential", accountId: "ordinary-user", userId: "ordinary-user", providerId: "credential",
      password: await context.password.hash("ordinary-password"),
      createdAt: new Date(now), updatedAt: new Date(now),
    } });
    const originalNow = Date.now;
    let response;
    try {
      Date.now = () => now;
      response = await auth.handler(new Request(`http://phone-duration.test/api/auth${paths[operation]}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: "http://phone-duration.test" },
        body: JSON.stringify({ phoneNumber: phone, ...(operation === "signIn" ? { password: "ordinary-password" } : {}) }),
      }));
    } finally { Date.now = originalNow; }
    const body = await response.json();
    const rows = await context.adapter.findMany({ model: "verification" });
    return {
      name, configured: seconds, operation,
      status: response.status, body,
      sender: sent.map((item) => ({
        kind: item.kind, phone: item.phoneNumber,
        codeLength: item.code.length, decimalCode: /^\d+$/.test(item.code),
        matchesStored: rows.some((row) => row.value === `${item.code}${operation === "signIn" ? "" : ":0"}`),
      })),
      records: rows.map((row) => ({
        identifier: row.identifier,
        lifetimeMillis: row.expiresAt.getTime() - now,
        attemptSuffix: row.value.endsWith(":0"),
      })),
    };
  } finally { database.close(); }
}

if (import.meta.main) {
  const cases = [];
  for (const [name, seconds] of [["omitted", undefined], ["zero", 0], ["fractional", 1.5]]) {
    for (const operation of Object.keys(paths)) cases.push(await capture(name, seconds, operation));
  }
  console.log(JSON.stringify({ version: "1.7.6", cases }, null, 2));
}
