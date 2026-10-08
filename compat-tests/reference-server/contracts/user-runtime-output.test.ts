import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { admin } from "better-auth/plugins";
import { build, cases, email, observe, options, owner, revive, secret, user } from "./user-runtime-contract";

async function outputCase(name: string, replacement: unknown, fail = false, calls = 1) {
  const memory = { user: [user()], session: [], account: [], verification: [] };
  const before = structuredClone(memory);
  const events: unknown[] = [];
  const auth = build(memory, { [name]: { transform: { output(value: unknown) {
    events.push(value);
    if (fail) throw new Error("user-output-stop");
    return replacement;
  } } });
  const { internalAdapter } = await auth.$context;
  if (fail) {
    await expect(internalAdapter.findUserById(owner)).rejects.toThrow("user-output-stop");
  } else {
    const result = await internalAdapter.findUserById(owner);
    const expected = { ...before.user[0], ...(calls ? { [name]: replacement } : {}) };
    expect(observe(result)).toStrictEqual(observe(expected));
    expect(Object.hasOwn(result!, name)).toBe(true);
    if (calls && replacement !== null && typeof replacement === "object") expect(result![name]).toBe(replacement);
  }
  expect(events.length).toBe(calls);
  if (calls) expect(observe(events[0])).toStrictEqual(observe(before.user[0][name]));
  expect(memory).toStrictEqual(before);
}

for (const field of cases.fields) {
  test(`User ${field.name} output retains its selected runtime value`, async () => {
    await outputCase(field.name, revive(field.replacement), false, "calls" in field ? field.calls : 1);
  });
}

for (const name of cases.representativeFields) {
  for (const value of cases.values) {
    test(`User ${name} output ${value.name} retains presence or propagates the callback error`, async () => {
      await outputCase(name, revive("value" in value ? value.value : undefined), "error" in value);
    });
  }
}

for (const sample of cases.verifiedConsumers) {
  test(`Email sign-in consumes ${sample.name} by truthiness before session issuance`, async () => {
    const memory = { user: [user()], session: [], verification: [], account: [{
      id: "runtime-account", accountId: owner, userId: owner, providerId: "credential", password: "hashed:runtime-password",
    }] };
    const events: unknown[] = [];
    const auth = betterAuth({
      ...options(memory, { emailVerified: { transform: { output(value: unknown) { events.push(value); return revive(sample.value); } } } }),
      emailAndPassword: { enabled: true, requireEmailVerification: true, password: {
        hash: async (password: string) => `hashed:${password}`,
        verify: async ({ hash, password }: { hash: string; password: string }) => hash === `hashed:${password}`,
      } },
    });
    const response = await auth.handler(new Request("http://localhost:3000/api/auth/sign-in/email", {
      method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify({ email, password: "runtime-password" }),
    }));
    expect(response.status).toBe(sample.status);
    expect(events).toStrictEqual([false]);
    expect(memory.session.length).toBe(sample.status === 200 ? 1 : 0);
    expect(response.headers.get("set-cookie")?.includes("better-auth.session_token=") ?? false).toBe(sample.status === 200);
    expect(memory.user[0].emailVerified).toBe(false);
  });
}

for (const sample of cases.roleConsumers) {
  test(`Admin role ${sample.name} uses truthy fallback before the string split operation`, async () => {
    const now = new Date();
    const memory = { user: [user()], account: [], verification: [], session: [{
      id: "runtime-session", userId: owner, token: "runtime-token", createdAt: now, updatedAt: now,
      expiresAt: new Date(Date.now() + 7 * 86_400_000),
    }] };
    const before = structuredClone(memory);
    const auth = betterAuth({
      ...options(memory, { role: { transform: { output() { return revive(sample.value); } } } }),
      plugins: [admin()],
    });
    const { createHMAC } = await import("@better-auth/utils/hmac");
    const signature = await createHMAC("SHA-256", "base64").sign(secret, "runtime-token");
    const response = await auth.handler(new Request("http://localhost:3000/api/auth/admin/list-users", {
      headers: { cookie: `better-auth.session_token=${encodeURIComponent(`runtime-token.${signature}`)}`, origin: "http://localhost:3000" },
    }));
    expect(response.status).toBe(sample.status);
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(memory).toStrictEqual(before);
  });
}

function authenticatedMemory() {
  const now = new Date();
  return { user: [user()], account: [], verification: [], session: [{
    id: "runtime-session", userId: owner, token: "runtime-token", createdAt: now, updatedAt: now,
    expiresAt: new Date(Date.now() + 7 * 86_400_000),
  }] };
}

async function sessionCookie() {
  const { createHMAC } = await import("@better-auth/utils/hmac");
  const signature = await createHMAC("SHA-256", "base64").sign(secret, "runtime-token");
  return `better-auth.session_token=${encodeURIComponent(`runtime-token.${signature}`)}`;
}

for (const sample of cases.emailConsumers) {
  test(`Selected User email ${sample.name} must support lowercase before verification delivery`, async () => {
    const memory = authenticatedMemory();
    const before = structuredClone(memory);
    const delivered: unknown[] = [];
    const auth = betterAuth({
      ...options(memory, { email: { transform: { output() { return revive(sample.value); } } } }),
      emailVerification: { async sendVerificationEmail({ user }: { user: { email: unknown } }) { delivered.push(user.email); } },
    });
    const response = await auth.handler(new Request("http://localhost:3000/api/auth/send-verification-email", {
      method: "POST", headers: { cookie: await sessionCookie(), "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify({ email }),
    }));
    expect(response.status).toBe(sample.status);
    expect(delivered.length).toBe(sample.sent);
    if (sample.sent) expect(observe(delivered[0])).toStrictEqual(sample.value);
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(memory).toStrictEqual(before);
  });
}

for (const sample of cases.banConsumers) {
  test(`User ban ${sample.name} consumes truthiness and Date before session mutation`, async () => {
    const memory = { user: [user()], session: [], verification: [], account: [{
      id: "runtime-account", accountId: owner, userId: owner, providerId: "credential", password: "hashed:runtime-password",
    }] };
    const before = structuredClone(memory.user[0]);
    const auth = betterAuth({
      ...options(memory, {
        banned: { transform: { output() { return revive(sample.banned); } } },
        banExpires: { transform: { output() { return revive(sample.expires); } } },
      }),
      plugins: [admin()],
      emailAndPassword: { enabled: true, password: {
        hash: async (password: string) => `hashed:${password}`,
        verify: async ({ hash, password }: { hash: string; password: string }) => hash === `hashed:${password}`,
      } },
    });
    const response = await auth.handler(new Request("http://localhost:3000/api/auth/sign-in/email", {
      method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify({ email, password: "runtime-password" }),
    }));
    expect(response.status).toBe(sample.status);
    expect(memory.session.length).toBe(sample.status === 200 ? 1 : 0);
    expect(response.headers.get("set-cookie")?.includes("better-auth.session_token=") ?? false).toBe(sample.status === 200);
    if (sample.clear) {
      expect([memory.user[0].banned, memory.user[0].banReason, memory.user[0].banExpires]).toStrictEqual([false, null, null]);
    } else {
      expect(memory.user[0]).toStrictEqual(before);
    }
  });
}

for (const sample of cases.changeEmailConsumers) {
  test(`Change-email ${sample.name} requires strict true before deferring the update`, async () => {
    const memory = authenticatedMemory();
    const base = options(memory, { emailVerified: { transform: { output() { return revive(sample.value); } } } });
    const auth = betterAuth({ ...base, user: { ...base.user, changeEmail: { enabled: true, updateEmailWithoutVerification: true } } });
    const response = await auth.handler(new Request("http://localhost:3000/api/auth/change-email", {
      method: "POST", headers: { cookie: await sessionCookie(), "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify({ newEmail: "changed@runtime.test" }),
    }));
    expect(response.status).toBe(sample.status);
    expect(memory.user[0].email).toBe(sample.changed ? "changed@runtime.test" : email);
    expect(response.headers.get("set-cookie")?.includes("better-auth.session_token=") ?? false).toBe(sample.changed);
  });
}
