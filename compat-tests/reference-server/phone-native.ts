import { betterAuth } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { phoneNumber } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { getCurrentAuthEndpointContext, runWithTransaction } from "@better-auth/core/context";
import { Database } from "bun:sqlite";

export async function createPhoneNativeFixture(profile: string, baseURL: string) {
  let mode = "normal";
  let events: any[] = [];
  const custom = profile.endsWith("custom");
  const absent = (value: any) => value === undefined ? { $undefined: true } : value;
  function record(phase: string, ctx: any) {
    events.push({ phase, path: ctx.path, ambient: absent(getCurrentAuthEndpointContext()?.path), body: absent(ctx.body), request: ctx.request ? new URL(ctx.request.url).pathname : null, header: ctx.headers?.get("x-literal") ?? null });
  }
  const options: any = {
    baseURL, secret: "phone-native-fixture-secret-longer-than-32", logger: { disabled: true }, rateLimit: { enabled: false },
    database: profile.endsWith("sqlite") ? new Database(":memory:") : undefined,
    hooks: {
      before: createAuthMiddleware(async ctx => {
        record("before", ctx);
        if (mode === "patch") return { context: { body: { code: "123456", patched: true } } };
        if (mode === "stop") return ctx.json({ status: false });
      }),
      after: createAuthMiddleware(async ctx => {
        record("after", ctx);
        if (mode === "replace") return ctx.json({ status: false });
        if (mode === "after-error") throw new APIError("BAD_REQUEST", { code: "AFTER_ERROR", message: "after rejected" });
      }),
    },
    plugins: [phoneNumber({
      allowedAttempts: 2,
      phoneNumberValidator: () => { events.push({ phase: "validator" }); return false; },
      callbackOnVerification: () => { events.push({ phase: "verified" }); },
      ...(custom ? { verifyOTP: async (_otp: any, ctx: any) => {
        record("verify", ctx);
        if (mode === "custom-error") throw new Error("verifier failed");
        if (mode === "custom-api") throw new APIError("FORBIDDEN", { code: "VERIFIER_ERROR", message: "verifier rejected" });
        return mode !== "custom-false";
      }} : {}),
    })],
  };
  if (options.database) { const migration = await getMigrations(options); await migration.runMigrations(); }
  const auth = betterAuth(options);
  const context = await auth.$context;
  const seed = async (input: any) => {
    await context.internalAdapter.deleteVerificationByIdentifier(input.phone);
    await context.internalAdapter.createVerificationValue({ identifier: input.phone, value: input.value ?? "123456:0", expiresAt: new Date(Date.now() + (input.expired ? -60_000 : 600_000)) });
  };
  return { handle: async (request: Request): Promise<Response> => {
    const path = new URL(request.url).pathname;
    if (path === "/health" || path === "/__health") return Response.json({ status: "ok" });
    if (path === "/__test/reset-state") return Response.json({ success: true });
    if (path !== "/__test/phone-native") return auth.handler(request);
    const input = await request.json();
    mode = input.mode ?? "normal"; events = [];
    if (input.action === "seed") { await seed(input); return Response.json({ status: true }); }
    const invoke = async () => {
      const args: any = { asResponse: false };
      if ("body" in input) args.body = input.body;
      if (input.headers !== undefined) args.headers = new Headers(input.headers);
      if (input.request) args.request = new Request(baseURL + "/original");
      return (auth.api as any).consumePhoneNumberOTP(args);
    };
    let result: any;
    try {
      if (input.action === "transaction") {
        result = await runWithTransaction(context.adapter, async () => {
          await seed(input);
          const value = await invoke();
          events.push({ phase: "transaction", remains: !!await context.internalAdapter.findVerificationValue(input.phone) });
          if (input.rollback) throw new Error("rollback requested");
          return value;
        });
      } else result = await invoke();
      result = { result };
    } catch (error: any) {
      result = { error: error.name === "APIError" ? { status: typeof error.status === "number" ? error.status : error.statusCode, body: error.body } : { ordinary: true, message: error.message } };
    }
    const stored = await context.internalAdapter.findVerificationValue(input.phone);
    const users = await context.adapter.count({ model: "user" });
    return Response.json({ ...result, events, stored: stored?.value ?? null, users });
  }};
}
