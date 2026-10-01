import { test } from "bun:test";
import assert from "node:assert/strict";
import { Database } from "bun:sqlite";
import observations from "./fallback-joins-upstream.json";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);

async function fixture(backend: string, limit?: number) {
  const db = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events: string[] = [];
  let fail = false;
  let failAccount = false;
  const options: any = {
    database: db,
    secret: "fallback-joins-contract-secret-longer-than-thirty-two",
    baseURL: "http://localhost:3000",
    logger: { disabled: true }, rateLimit: { enabled: false },
    socialProviders: { google: { clientId: "fixture", clientSecret: "fixture",
      verifyIdToken: async () => true,
      getUserInfo: async () => ({ user: { id: "alice-google", email: "alice@example.test", name: "Alice", emailVerified: true }, data: { sub: "alice-google", email: "alice@example.test", email_verified: true } }),
    } },
    databaseHooks: { account: { update: { before() { events.push("account:update"); } } } },
    advanced: { database: { defaultFindManyLimit: limit } },
    user: { validateUserInfo() { events.push("admission"); }, additionalFields: { username: { type: "string", required: false,
      transform: { output(value: any) { events.push(`user:${value}`); if (fail) throw new Error("user projection rejected"); return value; } },
    } } },
    account: { additionalFields: { accessToken: { type: "string", required: false,
      transform: { output(value: any) { events.push(`account:${value}`); if (failAccount) throw new Error("account projection rejected"); return value; } },
    } } },
    session: { additionalFields: { userAgent: { type: "string", required: false,
      transform: { output(value: any) { events.push(`session:${value}`); return value; } },
    } } },
  };
  if (db) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const ctx = await auth.$context;
  for (const name of ["alice", "bob"]) {
    await ctx.adapter.create({ model: "user", forceAllowId: true, data: {
      id: name, email: `${name}@example.test`, name, username: name,
      emailVerified: true, createdAt: new Date(), updatedAt: new Date(),
    } });
    for (let index = 0; index < 3; index++) {
      await ctx.internalAdapter.linkAccount({ userId: name, providerId: `provider-${index}`,
        accountId: `${name}-${index}`, accessToken: `${name}-${index}` });
    }
    await ctx.adapter.create({ model: "session", data: {
      userId: name, token: `${name}-session`, userAgent: name,
      expiresAt: new Date("2099-01-01T00:00:00Z"), createdAt: new Date(), updatedAt: new Date(),
    } });
  }
  events.length = 0;
  return { auth, ctx, events, reject: () => { fail = true; }, rejectAccount: () => { failAccount = true; }, close: () => db?.close() };
}

for (const backend of ["memory", "sqlite"]) {
  for (const limit of [undefined, 0, 1, 2]) {
    test(`${backend}: ordinary joins preserve ownership at limit ${limit}`, async () => {
      const f = await fixture(backend, limit);
      try {
        const owner = await f.ctx.internalAdapter.findAccountOwnerByKey({ providerId: "provider-1", accountId: "alice-1" });
        assert.equal(owner.kind, "owned");
        assert.equal(owner.user.id, "alice");
        assert.equal(owner.account.userId, "alice");
        assert.deepEqual(f.events, ["account:alice-1", "user:alice"]);
        const ownerEvents = f.events.splice(0);
        const user = await f.ctx.internalAdapter.findUserByEmail("ALICE@example.test", { includeAccounts: true });
        assert.equal(user.user.id, "alice");
        assert.equal(user.accounts.length, limit ?? 3);
        assert(user.accounts.every((row: any) => row.userId === "alice"));
        assert.deepEqual(f.events, ["user:alice", ...[0, 1, 2].slice(0, limit ?? 3).map(i => `account:alice-${i}`)]);
        const userEvents = f.events.splice(0);
        const session = await f.ctx.internalAdapter.findSession("alice-session");
        assert.equal(session.user.id, "alice");
        assert.equal(session.session.userId, "alice");
        assert.deepEqual(f.events, ["session:alice", "user:alice"]);
        const sessionEvents = f.events.splice(0);
        const sessions = await f.ctx.internalAdapter.findSessions(["bob-session", "alice-session"]);
        assert.equal(sessions.length, Math.min(limit ?? 2, 2));
        assert(sessions.every((row: any) => row.session.userId === row.user.id));
        const value = { backend, limit: limit ?? null, ownerEvents, userEvents, sessionEvents,
          accounts: user.accounts.map((row: any) => row.accountId),
          sessions: sessions.map((row: any) => row.user.id), batchEvents: [...f.events] };
        assert.deepEqual(value, observations.find(row => row.backend === backend && row.limit === (limit ?? null)));
        console.log(JSON.stringify(value));
      } finally { f.close(); }
    });
  }
  test(`${backend}: owner projection errors precede caller writes`, async () => {
    const f = await fixture(backend, 0);
    try {
      f.reject();
      await assert.rejects(f.ctx.internalAdapter.findAccountOwnerByKey({ providerId: "provider-1", accountId: "alice-1" }), /user projection rejected/);
      assert.deepEqual(f.events, ["account:alice-1", "user:alice"]);
      const account = await f.ctx.internalAdapter.findAccountByKey({ providerId: "provider-1", accountId: "alice-1" });
      assert.equal(account.accessToken, "alice-1");
    } finally { f.close(); }
  });
  test(`${backend}: OAuth owner read fails before admission and token refresh`, async () => {
    const f = await fixture(backend);
    try {
      await f.ctx.internalAdapter.linkAccount({ userId: "alice", providerId: "google", accountId: "alice-google", accessToken: "original" });
      f.events.length = 0;
      f.reject();
      const response = await f.auth.handler(new Request("http://localhost:3000/api/auth/sign-in/social", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ provider: "google", idToken: { token: "valid-fixture-token", accessToken: "replacement" } }),
      }));
      console.log(JSON.stringify({ diagnostic: "oauth-owner-read", status: response.status, body: await response.clone().text(), events: f.events }));
      assert.equal(response.status, 302);
      assert.deepEqual(f.events, ["account:original", "user:alice"]);
      const account = await f.ctx.internalAdapter.findAccountByKey({ providerId: "google", accountId: "alice-google" });
      assert.equal(account.accessToken, "original");
      console.log(JSON.stringify({ backend, oauthReadError: { status: response.status, location: response.headers.get("location"), events: f.events } }));
    } finally { f.close(); }
  });
  test(`${backend}: OAuth email account-page failure precedes linking`, async () => {
    const f = await fixture(backend);
    try {
      f.rejectAccount();
      const response = await f.auth.handler(new Request("http://localhost:3000/api/auth/sign-in/social", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ provider: "google", idToken: { token: "valid-fixture-token", accessToken: "replacement" } }),
      }));
      assert.equal(response.status, 302);
      assert.equal(response.headers.get("location"), "http://localhost:3000/api/auth/error?error=internal_server_error");
      assert.deepEqual(f.events, ["user:alice", "account:alice-0"]);
      assert.equal(await f.ctx.internalAdapter.findAccountByKey({ providerId: "google", accountId: "alice-google" }), null);
    } finally { f.close(); }
  });
}
