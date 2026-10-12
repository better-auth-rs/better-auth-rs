import assert from "node:assert/strict";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { compactVerify, decodeProtectedHeader } from "jose";
import { signVerificationPayload } from "./email-verification-payload-capture.mjs";
import { secondaryNativeNow as now } from "./secondary-native-shared.mjs";

export const origin = "https://native-email-consumers.test";
export const secret = "native-email-consumers-contract-secret-at-least-thirty-two-characters";
export const ownerEmail = "owner@native-email-consumers.test";
export const selectedEmail = "SELECTED@native-email-consumers.test";
const tables = ["user", "session", "account", "verification", "organization", "member", "invitation"];

export function nativeLower(native, label, result, failure, failAt) {
  const receiver = { label, calls: 0 };
  const method = function (...args) {
    native.call(`${label}:call`, this, receiver, args);
    receiver.calls++;
    if (failAt === "call") throw failure;
    return result;
  };
  Object.defineProperty(receiver, "toLowerCase", { configurable: true, get: function (...args) {
    native.call(`${label}:get`, this, receiver, args);
    if (failAt === "get") throw failure;
    return method;
  } });
  return receiver;
}

export function nativeUser(native, readEmail, verified = true) {
  const user = {
    id: "owner", name: "Owner", image: null,
    createdAt: new Date(now - 60_000), updatedAt: new Date(now - 60_000),
  };
  let reads = 0;
  Object.defineProperties(user, {
    email: { enumerable: true, configurable: true, get: function (...args) {
      native.call("user.email:get", this, user, args);
      return readEmail(++reads);
    } },
    emailVerified: { enumerable: true, configurable: true, get: function (...args) {
      native.call("user.emailVerified:get", this, user, args);
      return verified;
    } },
  });
  return { user, reads: () => reads };
}

export async function inspectToken(token) {
  const verified = await compactVerify(token, new TextEncoder().encode(secret), { algorithms: ["HS256"] });
  const payload = new TextDecoder().decode(verified.payload);
  const header = decodeProtectedHeader(token);
  assert.deepEqual(header, { alg: "HS256" });
  assert.equal(token, signVerificationPayload(payload, secret));
  return { token, header, payload, signatureVerified: true };
}

function observeAdapter(adapter, native) {
  const originals = new Map();
  for (const method of ["findOne", "findMany", "count", "create", "update", "updateMany", "delete", "deleteMany", "consumeOne"]) {
    if (typeof adapter[method] !== "function") continue;
    originals.set(method, adapter[method]);
    adapter[method] = new Proxy(adapter[method], { apply(target, receiver, args) {
      native.record(`adapter:${method}`, { arguments: native.snapshot(args) });
      return Reflect.apply(target, receiver, args);
    } });
  }
  return () => { for (const [method, original] of originals) adapter[method] = original; };
}

export async function withEmailConsumer(native, options, operation) {
  const memory = Object.fromEntries(tables.map(model => [model, []]));
  const sqlite = options.backend === "sqlite" ? new Database(":memory:") : undefined;
  let armed = false;
  let generated = 0;
  const injected = {
    session: {
      id: "injected-session", userId: "owner", token: "injected-session-token",
      createdAt: new Date(now - 60_000), updatedAt: new Date(now - 60_000),
      expiresAt: new Date(now + 3_600_000), ipAddress: null, userAgent: null,
      activeOrganizationId: null, activeTeamId: null,
    },
    user: options.user,
  };
  const hook = name => data => { if (armed) native.record(`organization:${name}`, { data: native.snapshot(data) }); };
  const authOptions = {
    database: sqlite ?? memoryAdapter(memory), baseURL: origin, secret,
    logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    session: { cookieCache: { enabled: false }, disableSessionRefresh: true },
    advanced: { database: { generateId: input => `${input.model}-${++generated}` } },
    emailVerification: { expiresIn: 3600, sendVerificationEmail: options.sender },
    hooks: { before: createAuthMiddleware(async ctx => {
      if (armed) native.record("endpoint:before", { path: ctx.path });
      ctx.context.session = injected;
    }) },
    plugins: [organization({
      requireEmailVerificationOnInvitation: true,
      organizationHooks: {
        beforeAcceptInvitation: hook("beforeAcceptInvitation"), afterAcceptInvitation: hook("afterAcceptInvitation"),
        beforeRejectInvitation: hook("beforeRejectInvitation"), afterRejectInvitation: hook("afterRejectInvitation"),
      },
    }), {
      id: "native-email-consumer-fields",
      schema: { invitation: { fields: { email: {
        type: "string", required: true, fieldName: "recipient_address",
        transform: {
          input(value) {
            if (armed) native.record("invitation.email:input", { value: native.snapshot(value) });
            return value;
          },
          output(value) {
            if (armed) native.record("invitation.email:output", { value: native.snapshot(value) });
            return armed && options.invitationEmail !== undefined ? options.invitationEmail : value;
          },
        },
      } } } },
    }],
  };
  let restore = () => {};
  try {
    if (sqlite) await (await getMigrations(authOptions)).runMigrations();
    const auth = betterAuth(authOptions);
    const context = await auth.$context;
    const create = (model, data) => context.adapter.create({ model, forceAllowId: true, data });
    for (const id of ["owner", "inviter"]) await create("user", {
      id, name: id, email: `${id}@native-email-consumers.test`, emailVerified: true,
      image: null, createdAt: new Date(now - 60_000), updatedAt: new Date(now - 60_000),
    });
    await create("organization", {
      id: "organization", name: "Organization", slug: "organization", logo: null,
      createdAt: new Date(now - 60_000), metadata: "{}",
    });
    await create("member", {
      id: "inviter-member", organizationId: "organization", userId: "inviter",
      role: "owner", createdAt: new Date(now - 60_000),
    });
    for (const [id, email] of [["invitation", ownerEmail], ["invitation-zero", "0"], ["invitation-selected", selectedEmail]]) {
      await create("invitation", {
        id, organizationId: "organization", email, role: "member", inviterId: "inviter",
        status: "pending", createdAt: new Date(now - 60_000), expiresAt: new Date(now + 3_600_000),
      });
    }
    const stored = () => Object.fromEntries(tables.map(model => [model,
      sqlite ? sqlite.query(`SELECT * FROM "${model}" ORDER BY "id"`).all() : memory[model],
    ]));
    const before = native.snapshot(stored());
    restore = observeAdapter(context.adapter, native);
    armed = true;
    const result = await operation({ auth, context, injected });
    armed = false;
    const after = native.snapshot(stored());
    const { response, ...serialized } = result;
    options.diagnostics?.push({ phase: "storage", scenario: options.scenario, ...serialized, before, after });
    assert.deepEqual(after, before, "Native email read failures and read-only endpoints must preserve complete storage");
    return { ...result, before, after };
  } finally {
    restore();
    sqlite?.close();
  }
}

export async function nativeEndpoint(native, operation, original, diagnostics) {
  let response;
  let headers;
  let cookies;
  const outcome = await native.outcome(async () => {
    let result;
    try {
      result = await operation();
    } catch (error) {
      diagnostics?.push({ phase: "endpoint-error", error: {
        name: error?.name, message: error?.message, stack: error?.stack, snapshot: native.snapshot(error),
      } });
      throw error;
    }
    assert.equal(result instanceof Response, false, "Observe the native API result before HTTP serialization");
    assert.ok(Object.hasOwn(result, "response") && result.headers instanceof Headers,
      "The native API call must return the response and Headers envelope");
    response = result.response;
    headers = [...result.headers];
    cookies = result.headers.getSetCookie();
    return response;
  }, original);
  return { outcome, response, headers, cookies };
}
