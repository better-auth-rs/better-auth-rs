import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { username } from "better-auth/plugins/username";
import { admin, emailOTP, phoneNumber } from "better-auth/plugins";

export const profiles = [
  "username-order-default", "username-order-pre", "username-order-post",
  "username-normalization-disabled", "username-no-display", "username-immutable-validation",
  "username-writes",
];

export async function createUsernameFixture(profile: string, baseURL: string) {
  if (!profiles.includes(profile)) throw new Error(`Unknown username profile: ${profile}`);
  const database = new Database(":memory:");
  const layered = profile.startsWith("username-order-") || profile === "username-writes";
  const mapped = profile === "username-order-post";
  const strict = profile === "username-immutable-validation";
  let calls: string[] = [];
  let events: any[] = [];
  let controls: { validator?: "deny" | "error"; displayValidator?: "deny" | "error"; echoUpdate?: boolean } = {};
  const fail = () => APIError.from("FORBIDDEN", { code: "USERNAME_CALLBACK_REJECTED", message: "Username callback rejected" });
  const validate = async (value: string) => {
    calls.push(`validate:${value}`);
    await Promise.resolve();
    if (controls.validator === "error") throw fail();
    return controls.validator !== "deny";
  };
  const displayValidate = async (value: string) => {
    calls.push(`display-validate:${value}`);
    await Promise.resolve();
    if (controls.displayValidator === "error") throw fail();
    return controls.displayValidator !== "deny";
  };
  const record = (kind: string, row: any, context: any) => events.push({
    kind, path: context?.path ?? null, http: Boolean(context?.request),
    ...("username" in row ? { username: row.username } : {}),
    ...("displayUsername" in row ? { displayUsername: row.displayUsername } : {}),
  });
  const pluginOptions: any = layered ? {
    minUsernameLength: 1,
    usernameValidator: validate,
    usernameNormalization(value: string) { calls.push(`normalize:${value}`); return `n${value}`; },
    displayUsernameNormalization(value: string) { calls.push(`display:${value}`); return `d${value}`; },
    ...(["username-order-default", "username-writes"].includes(profile) ? {} : { validationOrder: {
      username: mapped ? "post-normalization" : "pre-normalization",
      displayUsername: mapped ? "post-normalization" : "pre-normalization",
    } }),
  } : strict ? {
    immutableUsername: true, minUsernameLength: 3.5, maxUsernameLength: 6.5,
    usernameValidator: validate, displayUsernameValidator: displayValidate,
    displayUsernameNormalization(value: string) { calls.push(`display:${value}`); return value.trim(); },
    validationOrder: { displayUsername: "post-normalization" },
  } : profile === "username-no-display" ? { displayUsername: false } : { usernameNormalization: false, displayUsernameNormalization: false };
  if (mapped) pluginOptions.schema = { user: { fields: { username: "login_name", displayUsername: "display_label" } } };
  const options: any = {
    baseURL, database, secret: "username-fixture-secret-with-at-least-32-characters",
    rateLimit: { enabled: false }, session: { cookieCache: { enabled: false } },
    ...(mapped ? { user: { modelName: "username_users" } } : {}),
    emailAndPassword: { enabled: true, password: { hash: async (value: string) => `fixture:${value}`, verify: async ({ hash, password }: any) => hash === `fixture:${password}` } },
    plugins: [username(pluginOptions), ...(profile === "username-writes" ? [
      emailOTP({ generateOTP: () => "123456", sendVerificationOTP: async () => {} }),
      phoneNumber({ sendOTP: async () => {}, verifyOTP: async ({ code }) => code === "246810", signUpOnVerification: { getTempEmail: (phone: string) => `${phone.slice(1)}@phone.example.com` } }),
      admin(),
    ] : [])],
    databaseHooks: { user: {
      create: { before: async (row: any, ctx: any) => { record("create", row, ctx); } },
      update: { before: async (row: any, ctx: any) => { record("update", row, ctx); if (controls.echoUpdate) return { data: row }; } },
    } },
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context = await auth.$context;
  const table = mapped ? "username_users" : "user";
  const usernameColumn = mapped ? "login_name" : "username";
  const displayColumn = mapped ? "display_label" : "displayUsername";
  const columns = database.query(`PRAGMA table_info("${table}")`).all().map((row: any) => row.name);
  const snapshot = async () => ({
    calls: [...calls], events: [...events],
    schema: { username: columns.includes(usernameColumn), displayUsername: columns.includes(displayColumn), mapped },
    users: (await context.adapter.findMany({ model: "user" })).map((user: any) => ({
      email: user.email, username: user.username,
      ...("displayUsername" in user ? { displayUsername: user.displayUsername } : {}),
    })),
    rows: database.query(`SELECT email, "${usernameColumn}" AS username${columns.includes(displayColumn) ? `, "${displayColumn}" AS displayUsername` : ""} FROM "${table}" ORDER BY rowid`).all(),
  });
  return {
    close() { database.close(); },
    async handle(request: Request): Promise<Response> {
      const path = new URL(request.url).pathname;
      if (["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
      if (path === "/__test/reset-state") {
        for (const model of ["session", "account", "user"]) await context.adapter.deleteMany({ model, where: [] });
        calls = []; events = []; controls = {};
        return Response.json({ success: true });
      }
      if (path === "/__test/username") {
        if (request.method === "POST") { controls = await request.json(); calls = []; events = []; }
        return Response.json(await snapshot());
      }
      if (path === "/__test/username/native") {
        const input: any = await request.json();
        try {
          let body: unknown;
          if (input.operation === "create") body = await context.internalAdapter.createUser(input.data);
          else if (input.operation === "update") {
            const user = await context.adapter.findOne({ model: "user", where: [{ field: "email", value: input.email }] });
            if (!user) throw new Error("Fixture user does not exist");
            body = await context.internalAdapter.updateUser(user.id, input.data);
          } else if (input.operation === "endpoint-update") {
            body = await auth.api.updateUser({ body: input.data, headers: request.headers });
          } else if (input.operation === "endpoint-signup") {
            body = await auth.api.signUpEmail({ body: input.data, headers: request.headers });
          } else if (input.operation === "admin-create") {
            body = await auth.api.createUser({ body: input.data });
          } else throw new Error(`Unknown operation: ${input.operation}`);
          return Response.json({ status: 200, body });
        } catch (error: any) {
          if (error instanceof APIError) return Response.json({ status: error.statusCode, body: error.body });
          throw error;
        }
      }
      return auth.handler(request);
    },
  };
}
