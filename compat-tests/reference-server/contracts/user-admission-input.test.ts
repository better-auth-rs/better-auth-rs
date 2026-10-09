import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { anonymous, emailOTP, phoneNumber } from "better-auth/plugins";

test("Memory: signup preserves native phone fields from enabled plugin declarations", async () => {
  const memory = { user: [], session: [], account: [], verification: [] };
  const events: [string, any][] = [];
  const auth = betterAuth({
    database: memoryAdapter(memory),
    baseURL: "https://admission.test",
    secret: "user-admission-contract-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    emailAndPassword: {
      enabled: true, autoSignIn: false,
      password: {
        hash: async (password: string) => `fixture:${password}`,
        verify: async ({ hash, password }: any) => hash === `fixture:${password}`,
      },
    },
    user: { validateUserInfo({ user, source }: any) {
      expect(source).toStrictEqual({ method: "email-password", action: "create-user" });
      events.push(["admission", structuredClone(user)]);
    } },
    databaseHooks: {
      user: { create: {
        before(user: any) { events.push(["before", structuredClone(user)]); },
        after(user: any) { events.push(["after", structuredClone(user)]); },
      } },
      account: { create: { before() { events.push(["account", null]); } } },
    },
    plugins: [phoneNumber({ sendOTP: async () => {} }), anonymous()],
  });
  const response = await auth.handler(new Request("https://admission.test/api/auth/sign-up/email", {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://admission.test" },
    body: JSON.stringify({
      name: "Phone Owner", email: "phone@admission.test", password: "Password123!", phoneNumber: 7,
    }),
  }));
  expect(response.status).toBe(200);
  expect(events.map(([phase]) => phase)).toStrictEqual(["admission", "before", "account", "after"]);
  const admitted = events[0][1];
  expect(admitted).toStrictEqual({
    createdAt: expect.any(Date), updatedAt: expect.any(Date),
    email: "phone@admission.test", name: "Phone Owner", image: undefined,
    phoneNumber: 7, isAnonymous: false, emailVerified: false,
  });
  expect(Object.keys(admitted)).toStrictEqual([
    "createdAt", "updatedAt", "email", "name", "image", "phoneNumber", "isAnonymous", "emailVerified",
  ]);
  expect(events[1][1]).toStrictEqual(admitted);
  expect(Object.keys(events[1][1])).toStrictEqual(Object.keys(admitted));
  const context = await auth.$context;
  const stored = await context.adapter.findOne<any>({
    model: "user", where: [{ field: "email", value: "phone@admission.test" }],
  });
  expect(stored).toStrictEqual({
    id: expect.any(String), name: "Phone Owner", email: "phone@admission.test",
    emailVerified: false, image: undefined,
    createdAt: admitted.createdAt, updatedAt: admitted.updatedAt,
    phoneNumber: 7, phoneNumberVerified: undefined, isAnonymous: false,
  });
  expect(events[3][1]).toStrictEqual(stored);
  expect(await response.json()).toStrictEqual(JSON.parse(JSON.stringify({ token: null, user: stored })));
  expect(await context.adapter.count({ model: "user" })).toBe(1);
  expect(await context.adapter.count({ model: "account" })).toBe(1);
  expect(await context.adapter.count({ model: "session" })).toBe(0);
});

for (const sqlite of [false, true]) {
  test(`${sqlite ? "SQLite" : "Memory"}: admission and hooks share prepared User values and normalization failures`, async () => {
    const database = sqlite ? new Database(":memory:") : null;
    const memory = { user: [], session: [], account: [], verification: [] };
    const createdAt = new Date(1_600_000_000_000);
    const metadata = { source: "runtime" };
    let input: Record<string, any> = {
      name: "Runtime name", email: "RUNTIME@ADMISSION.TEST", emailVerified: undefined,
      createdAt, metadata, ownUndefined: undefined,
    };
    const events: [string, any][] = [];
    const options: any = {
      database: database ?? memoryAdapter(memory),
      baseURL: "https://admission.test",
      secret: "user-admission-contract-secret-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      user: {
        additionalFields: { metadata: { type: "json", required: false } },
        validateUserInfo(data: any) { events.push(["admission", data.user]); },
      },
      databaseHooks: { user: { create: {
        before(data: any) { events.push(["before", data]); },
        after(data: any) { events.push(["after", data]); },
      } } },
      plugins: [{ id: "admission-contract", endpoints: {
        admissionContract: createAuthEndpoint("/admission-contract", { method: "GET" }, async ctx => {
          try {
            const user = await ctx.context.internalAdapter.createUser(input, { method: "contract" });
            return ctx.json({ user });
          } catch (error) {
            return ctx.json({ error: (error as Error).message, name: (error as Error).name });
          }
        }),
      } }],
    };
    try {
      if (database) await (await getMigrations(options)).runMigrations();
      const auth = betterAuth(options);
      const create = async () => (await auth.handler(new Request("https://admission.test/api/auth/admission-contract"))).json();
      const result = await create();
      expect(result.error).toBeUndefined();
      expect(events.map(event => event[0])).toStrictEqual(["admission", "before", "after"]);
      const admitted = events[0][1];
      const before = events[1][1];
      expect(admitted).toBe(before);
      expect(Object.keys(admitted)).toStrictEqual(Object.keys(before));
      for (const name of Object.keys(admitted)) expect(admitted[name]).toBe(before[name]);
      expect(admitted).toMatchObject({ name: "Runtime name", email: "runtime@admission.test" });
      expect(Object.hasOwn(admitted, "emailVerified")).toBe(true);
      expect(Object.hasOwn(admitted, "ownUndefined")).toBe(true);
      expect(admitted.emailVerified).toBeUndefined();
      expect(admitted.ownUndefined).toBeUndefined();
      expect(admitted.createdAt).toBe(createdAt);
      expect(admitted.metadata).toBe(metadata);
      expect(admitted.updatedAt).toBeInstanceOf(Date);
      expect(result.user.emailVerified).toBe(false);

      events.length = 0;
      input = { name: "Invalid", email: {} };
      const rejected = await create();
      expect(rejected.name).toBe("TypeError");
      expect(rejected.error).toContain("toLowerCase");
      expect(events).toStrictEqual([]);
      const context = await auth.$context;
      expect(await context.adapter.count({ model: "user" })).toBe(1);
    } finally {
      database?.close();
    }
  });
}

for (const sqlite of [false, true]) {
  for (const imageProvided of [false, true]) {
    test(`${sqlite ? "SQLite" : "Memory"}: email OTP owns verified and reserved User fields with image=${imageProvided}`, async () => {
      const database = sqlite ? new Database(":memory:") : null;
      const memory = { user: [], session: [], account: [], verification: [] };
      const validators: string[] = [];
      const events: [string, any][] = [];
      const sources: any[] = [];
      const deliveries: any[] = [];
      const email = "otp@admission.test";
      const image = "https://admission.test/avatar.png";
      const options: any = {
        database: database ?? memoryAdapter(memory),
        baseURL: "https://admission.test",
        secret: "user-admission-contract-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        user: {
          additionalFields: {
            ...Object.fromEntries(["email", "name", "image", "otp"].map(name => [name, {
              type: "string", required: false,
              ...(name === "otp" ? { fieldName: "username" } : {}),
              validator: { input: { "~standard": { validate() {
                validators.push(name);
                return { value: `parsed-${name}` };
              } } } },
            }])),
            emailVerified: { type: "boolean", required: false, defaultValue: false },
          },
          validateUserInfo({ user, source }: any) {
            events.push(["admission", structuredClone(user)]);
            sources.push(structuredClone(source));
          },
        },
        databaseHooks: { user: { create: {
          before(user: any) { events.push(["before", structuredClone(user)]); },
          after(user: any) { events.push(["after", structuredClone(user)]); },
        } } },
        plugins: [emailOTP({
          generateOTP: () => "123456",
          async sendVerificationOTP(message) { deliveries.push(message); },
        })],
      };
      try {
        if (database) await (await getMigrations(options)).runMigrations();
        const auth = betterAuth(options);
        const post = (path: string, body: unknown) => auth.handler(new Request(`https://admission.test/api/auth${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: "https://admission.test" },
          body: JSON.stringify(body),
        }));
        const sent = await post("/email-otp/send-verification-otp", { email: email.toUpperCase(), type: "sign-in" });
        expect(sent.status).toBe(200);
        expect(await sent.json()).toStrictEqual({ success: true });
        expect(deliveries).toStrictEqual([{ email, otp: "123456", type: "sign-in" }]);
        const response = await post("/sign-in/email-otp", {
          email: email.toUpperCase(), otp: "123456", name: "OTP Owner",
          ...(imageProvided ? { image } : {}),
        });
        expect(response.status).toBe(200);
        const result = await response.json();
        expect(validators).toStrictEqual([]);
        expect(sources).toStrictEqual([{ method: "email-otp", action: "create-user" }]);
        expect(events.map(([phase]) => phase)).toStrictEqual(["admission", "before", "after"]);
        const admitted = events[0][1];
        expect(admitted).toStrictEqual({
          createdAt: expect.any(Date), updatedAt: expect.any(Date),
          emailVerified: true, email, name: "OTP Owner", image: imageProvided ? image : undefined,
        });
        expect(Object.keys(admitted)).toStrictEqual(["createdAt", "updatedAt", "emailVerified", "email", "name", "image"]);
        expect(events[1][1]).toStrictEqual(admitted);
        expect(Object.hasOwn(admitted, "image")).toBe(true);
        const context = await auth.$context;
        const stored = await context.adapter.findOne({ model: "user", where: [{ field: "email", value: email }] });
        expect(stored).toStrictEqual({
          id: expect.any(String), name: "OTP Owner", email, emailVerified: true,
          image: imageProvided ? image : sqlite ? null : undefined,
          createdAt: admitted.createdAt, updatedAt: admitted.updatedAt,
          otp: sqlite ? null : undefined,
        });
        expect(events[2][1]).toStrictEqual(stored);
        const session = await context.adapter.findOne<any>({ model: "session", where: [{ field: "userId", value: result.user.id }] });
        expect(session?.token).toBeString();
        expect(result).toStrictEqual(JSON.parse(JSON.stringify({ token: session.token, user: stored })));
        expect(await context.adapter.count({ model: "user" })).toBe(1);
        expect(await context.adapter.count({ model: "session" })).toBe(1);
        expect(await context.adapter.count({ model: "verification" })).toBe(0);
      } finally {
        database?.close();
      }
    });
  }
}

for (const sqlite of [false, true]) {
  for (const [mode, protectedSignup] of [
    ["normalize", true], ["native", true], ["api", true],
    ["forbidden", true], ["forbidden", false], ["cancel", true],
    ["account", true], ["after", true],
  ] as const) {
    test(`${sqlite ? "SQLite" : "Memory"}: signup ${mode} with protection=${protectedSignup} keeps the creation error boundary`, async () => {
      const database = sqlite ? new Database(":memory:") : null;
      const memory = { user: [], session: [], account: [], verification: [] };
      const events: string[] = [];
      const options: any = {
        database: database ?? memoryAdapter(memory),
        baseURL: "https://admission.test",
        secret: "user-admission-contract-secret-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false },
        emailAndPassword: {
          enabled: true, autoSignIn: !protectedSignup,
          password: {
            hash: async (password: string) => `fixture:${password}`,
            verify: async ({ hash, password }: any) => hash === `fixture:${password}`,
          },
        },
        user: {
          additionalFields: {
            emailVerified: { type: "boolean", required: false },
            ...(mode === "normalize" ? { email: { type: "json", defaultValue: {} } } : {}),
          },
          validateUserInfo({ user }: any) {
            events.push("admission");
            expect(user.emailVerified).toBe(false);
            expect(Object.hasOwn(user, "image")).toBe(true);
            expect(user.image).toBeUndefined();
          },
        },
        databaseHooks: {
          user: { create: {
            before(user: any) {
              events.push("before");
              expect(Object.hasOwn(user, "image")).toBe(true);
              expect(user.image).toBeUndefined();
              if (mode === "native") throw new Error("private user failure");
              if (mode === "api") throw new APIError("INTERNAL_SERVER_ERROR", {
                code: "APPLICATION_FAILURE", message: "Public failure",
              }, { "x-hook": "preserved" });
              if (mode === "forbidden") throw new APIError("FORBIDDEN", {
                code: "APPLICATION_DENIED", message: "Application denied user",
              });
              if (mode === "cancel") return false;
            },
            after() {
              events.push("after");
              if (mode === "after") throw new Error("private committed failure");
            },
          } },
          account: { create: { before() {
            events.push("account");
            if (mode === "account") throw new Error("private account failure");
          } } },
        },
      };
      try {
        if (database) await (await getMigrations(options)).runMigrations();
        const auth = betterAuth(options);
        const response = await auth.handler(new Request("https://admission.test/api/auth/sign-up/email", {
          method: "POST",
          headers: { "content-type": "application/json", origin: "https://admission.test" },
          body: JSON.stringify({ name: "Signup", email: "signup@admission.test", password: "Password123!", emailVerified: true }),
        }));
        const status = ["normalize", "native"].includes(mode) ? 422
          : mode === "cancel" ? 400
          : mode === "forbidden" ? protectedSignup ? 200 : 403 : 500;
        expect(response.status).toBe(status);
        if (["normalize", "native", "cancel"].includes(mode)) {
          expect(await response.json()).toStrictEqual({ code: "FAILED_TO_CREATE_USER", message: "Failed to create user" });
        } else if (mode === "api") {
          expect(await response.json()).toStrictEqual({ code: "APPLICATION_FAILURE", message: "Public failure" });
          expect(response.headers.get("x-hook")).toBe("preserved");
        } else if (mode === "forbidden" && !protectedSignup) {
          expect(await response.json()).toStrictEqual({ code: "APPLICATION_DENIED", message: "Application denied user" });
        } else if (mode === "account" || mode === "after") {
          expect(await response.text()).toBe("");
        } else {
          const body = await response.json();
          expect(body.token).toBeNull();
          expect(body.user.email).toBe("signup@admission.test");
        }
        expect(events).toStrictEqual(mode === "normalize" ? []
          : mode === "account" ? ["admission", "before", "account"]
          : mode === "after" ? ["admission", "before", "account", "after"]
          : ["admission", "before"]);
        const context = await auth.$context;
        expect(await context.adapter.count({ model: "user" })).toBe(mode === "after" ? 1 : 0);
        expect(await context.adapter.count({ model: "account" })).toBe(mode === "after" ? 1 : 0);
        expect(await context.adapter.count({ model: "session" })).toBe(0);
      } finally {
        database?.close();
      }
    });
  }
}
