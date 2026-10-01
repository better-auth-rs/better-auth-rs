import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { admin, emailOTP } from "better-auth/plugins";
import { apiKey } from "@better-auth/api-key";

export async function runDynamicNative(input: { scenario: string }) {
  const database = new Database(":memory:");
  const events: any[] = [];
  let auth: any;
  const transaction = input.scenario.startsWith("transaction-");
  const otpPlugin = emailOTP({ sendVerificationOTP: async () => {}, generateOTP: (_: unknown, ctx: any) => {
    events.push({ event: "generate", baseURL: ctx.context.baseURL });
    return "123456";
  } });
  const options: any = {
    database,
    secret: "dynamic-native-fixture-secret-at-least-thirty-two-characters",
    baseURL: { allowedHosts: ["*.auth.test"], ...(input.scenario === "fallback" ? { fallback: "https://fallback.auth.test" } : {}) },
    logger: { disabled: true }, rateLimit: { enabled: false },
    trustedOrigins: async (request?: Request) => {
      events.push({ event: "origins", host: request?.headers.get("host") ?? null });
      return ["https://alpha.auth.test"];
    },
    emailAndPassword: { enabled: true, password: { hash: async () => "fixture-hash", verify: async () => true } },
    user: { async validateUserInfo(data: any, ctx: any) {
      if (!transaction) return;
      const email = data.user.email;
      const before = await otpPlugin.endpoints.getVerificationOTP({ query: { email, type: "sign-in" }, context: ctx.context });
      const created = await otpPlugin.endpoints.createVerificationOTP({ body: { email, type: "sign-in" }, context: ctx.context });
      const after = await otpPlugin.endpoints.getVerificationOTP({ query: { email, type: "sign-in" }, context: ctx.context });
      events.push({ event: "admission", before: before.otp, created, after: after.otp });
      if (input.scenario === "transaction-deny") return { error: "fixture_denied" };
    } },
    plugins: [admin(), apiKey(), otpPlugin],
  };
  await (await getMigrations(options)).runMigrations();
  auth = betterAuth(options);
  const context = await auth.$context;
  const seed = await context.adapter.create({ model: "user", data: { email: "seed@example.com", name: "Seed", emailVerified: false, createdAt: new Date(), updatedAt: new Date() } });
  events.length = 0;
  const calls: any[] = [];
  async function call(op: string, action: () => Promise<unknown>) {
    try { calls.push({ op, ok: true, value: await action() }); }
    catch { calls.push({ op, ok: false }); }
  }
  if (transaction) {
    const response = await auth.handler(new Request("https://alpha.auth.test/api/auth/sign-up/email", {
      method: "POST", headers: { host: "alpha.auth.test", origin: "https://alpha.auth.test", "content-type": "application/json" },
      body: JSON.stringify({ name: "Signup", email: "signup@example.com", password: "fixture-password" }),
    }));
    calls.push({ op: "signup", ok: response.ok, status: response.status });
  } else if (input.scenario === "headers") {
    await call("admin", async () => {
      await auth.api.createUser({ headers: new Headers({ host: "alpha.auth.test" }), body: { name: "Admin", email: "admin@example.com" } });
      return true;
    });
  } else {
    await call("admin", async () => { await auth.api.createUser({ body: { name: "Admin", email: "admin@example.com" } }); return true; });
    await call("otp-create", () => auth.api.createVerificationOTP({ body: { email: "native@example.com", type: "sign-in" } }));
    await call("otp-get", async () => (await auth.api.getVerificationOTP({ query: { email: "native@example.com", type: "sign-in" } })).otp);
    let key: any;
    await call("key-create", async () => { key = await auth.api.createApiKey({ body: { userId: seed.id, name: "Native key" } }); return key.name; });
    await call("key-update", async () => (await auth.api.updateApiKey({ body: { userId: seed.id, keyId: key?.id ?? "missing", name: "Updated key" } })).name);
    await call("key-verify", async () => (await auth.api.verifyApiKey({ body: { key: key?.key ?? "missing" } })).valid);
  }
  const email = transaction ? "signup@example.com" : "native@example.com";
  const snapshot = {
    admin: !!database.query('SELECT id FROM "user" WHERE email = ?').get("admin@example.com"),
    signup: !!database.query('SELECT id FROM "user" WHERE email = ?').get("signup@example.com"),
    otp: !!database.query('SELECT id FROM "verification" WHERE identifier = ?').get(`sign-in-otp-${email}`),
    keys: (database.query('SELECT COUNT(*) AS count FROM "apikey"').get() as any).count,
  };
  database.close();
  return { calls, events, snapshot };
}
