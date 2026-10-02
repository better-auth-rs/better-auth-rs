import { Database } from "bun:sqlite";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { twoFactor } = await import(`${modules}/better-auth/dist/plugins/two-factor/index.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);

const origin = "http://two-factor-duration.test";
const userId = "ordinary-user";
const email = "ordinary@two-factor-duration.test";
const password = "ordinary-password";

function selectedCookie(response, suffix) {
  const prefix = `better-auth.${suffix}=`;
  const headers = response.headers.getSetCookie().filter((header) => header.startsWith(prefix));
  if (headers.length !== 1) throw new Error(`Expected one ${suffix} issuance cookie`);
  return headers[0];
}

function cookieShape(header) {
  const [pair, ...attributes] = header.split("; ");
  const shape = { name: pair.slice(0, pair.indexOf("=")), attributes: {} };
  for (const attribute of attributes) {
    const separator = attribute.indexOf("=");
    const key = (separator < 0 ? attribute : attribute.slice(0, separator)).toLowerCase();
    shape.attributes[key] = separator < 0 ? true : attribute.slice(separator + 1);
  }
  return shape;
}

export async function capture(name, configured, operation) {
  const database = new Database(":memory:");
  const sent = [];
  const pluginOptions = {
    totpOptions: { disable: true },
    otpOptions: { sendOTP(data) { sent.push(data); } },
    ...(name === "omitted" ? {} : {
      [operation === "challenge" ? "twoFactorCookieMaxAge" : "trustDeviceMaxAge"]: configured,
    }),
  };
  const options = {
    database,
    baseURL: origin,
    secret: "ordinary-two-factor-duration-secret-longer-than-32-characters",
    emailAndPassword: { enabled: true },
    telemetry: { enabled: false },
    logger: { disabled: true },
    rateLimit: { enabled: false },
    plugins: [twoFactor(pluginOptions)],
  };
  try {
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    const context = await auth.$context;
    const now = Date.now();
    await context.adapter.create({ model: "user", forceAllowId: true, data: {
      id: userId, name: "Two Factor Duration", email, emailVerified: true,
      twoFactorEnabled: true, createdAt: new Date(now), updatedAt: new Date(now),
    } });
    await context.adapter.create({ model: "account", forceAllowId: true, data: {
      id: "ordinary-credential", accountId: userId, userId, providerId: "credential",
      password: await context.password.hash(password),
      createdAt: new Date(now), updatedAt: new Date(now),
    } });
    const request = (path, body, cookie) => auth.handler(new Request(`${origin}/api/auth${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json", origin,
        ...(cookie ? { cookie } : {}),
      },
      body: JSON.stringify(body),
    }));
    const issue = async () => {
      const signIn = await request("/sign-in/email", { email, password });
      if (signIn.status !== 200) throw new Error(`Ordinary sign-in failed: ${signIn.status}`);
      if (operation === "challenge") return signIn;
      const pending = selectedCookie(signIn, "two_factor").split(";")[0];
      const send = await request("/two-factor/send-otp", {}, pending);
      if (send.status !== 200 || sent.length !== 1) throw new Error("Ordinary OTP delivery failed");
      return request("/two-factor/verify-otp", { code: sent[0].otp, trustDevice: true }, pending);
    };
    const originalNow = Date.now;
    const issuedAt = originalNow();
    let response;
    try {
      Date.now = () => issuedAt;
      response = await issue();
    } finally { Date.now = originalNow; }
    const body = await response.json();
    const suffix = operation === "challenge" ? "two_factor" : "trust_device";
    const rows = await context.adapter.findMany({ model: "verification" });
    const records = rows.filter((row) => operation === "challenge"
      ? row.identifier.startsWith("2fa-")
      : row.identifier.startsWith("trust-device-")).map((row) => ({
      kind: row.identifier.startsWith("2fa-attempts-") ? "attempts" : operation,
      value: row.value,
      lifetimeMillis: row.expiresAt.getTime() - issuedAt,
    })).sort((a, b) => a.kind.localeCompare(b.kind));
    return {
      name, configured, operation,
      status: response.status,
      body: operation === "challenge" ? body : {
        tokenPresent: typeof body.token === "string" && body.token.length > 0,
        user: { id: body.user.id, name: body.user.name, email: body.user.email,
          emailVerified: body.user.emailVerified, twoFactorEnabled: body.user.twoFactorEnabled },
      },
      cookie: cookieShape(selectedCookie(response, suffix)),
      sender: sent.map(({ user, otp }) => ({
        userId: user.id, email: user.email, codeLength: otp.length, decimalCode: /^\d+$/.test(otp),
      })),
      records,
    };
  } finally { database.close(); }
}

if (import.meta.main) {
  const cases = [];
  for (const [name, configured] of [["omitted", undefined], ["zero", 0], ["fractional", 1.5]]) {
    for (const operation of ["challenge", "trust"]) cases.push(await capture(name, configured, operation));
  }
  console.log(JSON.stringify({ version: "1.7.6", cases }, null, 2));
}
