import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { organization, testUtils } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";

async function fixture(databaseEnabled: boolean, extra: any = {}) {
  const database = databaseEnabled ? new Database(":memory:") : undefined;
  const generated: any[] = [];
  const options: any = {
    database,
    baseURL: "https://test-utils.example/auth",
    basePath: "/auth",
    secret: "test-utils-fixture-secret-at-least-thirty-two-characters",
    logger: { disabled: true },
    rateLimit: { enabled: false },
    session: { expiresIn: 400, additionalFields: { label: { type: "string", defaultValue: "default", required: false } } },
    advanced: {
      useSecureCookies: false,
      database: { generateId: (input: any) => { generated.push(input); return `${input.model}-${generated.length}`; } },
      cookies: { session_token: { name: "fixture.token", attributes: { path: "/custom", domain: ".ignored.example", maxAge: 90, sameSite: "strict", httpOnly: false } } },
    },
    plugins: [testUtils({ captureOTP: true })],
    ...extra,
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context: any = await auth.$context;
  return { auth, context, helpers: context.test, database, generated };
}

for (const databaseEnabled of [false, true]) {
  const mode = databaseEnabled ? "sqlite" : "implicit";
  test(`${mode}: factories stay local and saved/deleted records use the adapter`, async () => {
    const { context, helpers, database, generated } = await fixture(databaseEnabled);
    try {
      expect(helpers.createOrganization).toBeUndefined();
      const createdAt = new Date("2020-01-01T00:00:00.000Z");
      const draft = helpers.createUser({ id: "supplied-user", email: "TEST@example.com", createdAt, image: null });
      expect(generated).toEqual([{ model: "user" }]);
      expect(draft).toMatchObject({ id: "supplied-user", email: "TEST@example.com", name: "Test User", emailVerified: true, image: null, createdAt });
      expect(await context.internalAdapter.findUserById(draft.id)).toBeNull();
      const saved = await helpers.saveUser(draft);
      expect(saved).toMatchObject({ id: "supplied-user", email: "test@example.com", createdAt });
      await helpers.deleteUser(saved.id);
      expect(await context.internalAdapter.findUserById(saved.id)).toBeNull();
    } finally { database?.close(); }
  });

  test(`${mode}: login ignores standard session overrides and issues usable credentials`, async () => {
    const { auth, context, helpers, database } = await fixture(databaseEnabled);
    try {
      const user = await helpers.saveUser(helpers.createUser({ email: "login@example.com" }));
      const before = Date.now();
      const start = Math.floor(before / 1000);
      const result = await helpers.login({ userId: user.id, session: {
        id: "injected", token: "injected", userId: "other", expiresAt: new Date(0), createdAt: new Date(0), updatedAt: new Date(0), ipAddress: "injected", userAgent: "injected", label: "selected",
      } });
      expect(result.session.id).not.toBe("injected");
      expect(result.token).not.toBe("injected");
      expect(result.token).toBe(result.session.token);
      expect(result.session).toMatchObject({ userId: user.id, label: "selected", ipAddress: "", userAgent: "" });
      expect(result.session.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 400_000);
      expect(result.session.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 400_000);
      expect(result.user.id).toBe(user.id);
      expect(result.headers.get("cookie")).toBe(`fixture.token=${result.cookies[0].value}`);
      expect(result.cookies).toHaveLength(1);
      expect(result.cookies[0]).toMatchObject({ name: "fixture.token", domain: "test-utils.example", path: "/custom", httpOnly: false, secure: false, sameSite: "Strict" });
      expect(result.cookies[0].expires).toBeGreaterThanOrEqual(start + 90);
      expect(result.cookies[0].expires).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 90);
      const response: any = await auth.api.getSession({ headers: result.headers });
      expect(response.user.id).toBe(user.id);
      expect(response.session.token).toBe(result.token);
      expect((await context.internalAdapter.listSessions(user.id)).map((entry: any) => entry.token)).toEqual([result.token]);
      await expect(helpers.login({ userId: "missing" })).rejects.toThrow("User not found: missing");
    } finally { database?.close(); }
  });

  test(`${mode}: headers and browser cookies each create a distinct session`, async () => {
    const { context, helpers, database } = await fixture(databaseEnabled);
    try {
      const user = await helpers.saveUser(helpers.createUser({ email: "cookies@example.com" }));
      const headers = await helpers.getAuthHeaders({ userId: user.id });
      const cookies = await helpers.getCookies({ userId: user.id, domain: "browser.example", session: { label: "browser" } });
      expect(cookies[0].domain).toBe("browser.example");
      expect(headers.get("cookie")).not.toContain(cookies[0].value);
      const sessions = await context.internalAdapter.listSessions(user.id);
      expect(sessions).toHaveLength(2);
      expect(sessions.map((entry: any) => entry.label).sort()).toEqual(["browser", "default"]);
    } finally { database?.close(); }
  });

  test(`${mode}: OTP capture strips only the listed prefix and remains instance scoped`, async () => {
    const first = await fixture(databaseEnabled);
    const second = await fixture(databaseEnabled);
    try {
      for (const [identifier, value, key, expected] of [
        ["sign-in-otp-a@example.com", "123456:3", "a@example.com", "123456"],
        ["email-verification-otp-b@example.com", "234567:0", "b@example.com", "234567"],
        ["forget-password-otp-c@example.com", "345678:1", "c@example.com", "345678"],
        ["phone-verification-otp-+1234", "456789:2", "+1234", "456789"],
        ["custom-a@example.com", "raw:9", "custom-a@example.com", "raw"],
      ]) {
        await first.context.internalAdapter.createVerificationValue({ identifier, value, expiresAt: new Date(Date.now() + 60_000) });
        expect(first.helpers.getOTP(key)).toBe(expected);
        expect(second.helpers.getOTP(key)).toBeUndefined();
      }
      await first.context.internalAdapter.createVerificationValue({ identifier: "sign-in-otp-a@example.com", value: ":4", expiresAt: new Date(Date.now() + 60_000) });
      expect(first.helpers.getOTP("a@example.com")).toBe("123456");
      first.helpers.clearOTPs();
      expect(first.helpers.getOTP("a@example.com")).toBeUndefined();
      expect(await first.context.internalAdapter.findVerificationValue("sign-in-otp-a@example.com")).not.toBeNull();
    } finally { first.database?.close(); second.database?.close(); }
  });
}

test("organization helpers are opt-in and remove memberships before the organization", async () => {
  const { context, helpers, database } = await fixture(true, { plugins: [organization(), testUtils()] });
  try {
    expect(helpers.getOTP).toBeUndefined();
    const user = await helpers.saveUser(helpers.createUser({ email: "member@example.com" }));
    const draft = helpers.createOrganization({ id: "org-supplied", name: "Example Organization", slug: "example" });
    expect(await context.adapter.findOne({ model: "organization", where: [{ field: "id", value: draft.id }] })).toBeNull();
    const organization = await helpers.saveOrganization(draft);
    expect(organization.id).toBe(draft.id);
    const member = await helpers.addMember({ userId: user.id, organizationId: organization.id, role: "owner" });
    expect(member).toMatchObject({ userId: user.id, organizationId: organization.id, role: "owner" });
    await helpers.deleteOrganization(organization.id);
    expect(await context.adapter.findOne({ model: "organization", where: [{ field: "id", value: organization.id }] })).toBeNull();
    expect(await context.adapter.findOne({ model: "member", where: [{ field: "id", value: member.id }] })).toBeNull();
    expect(await context.internalAdapter.findUserById(user.id)).not.toBeNull();
  } finally { database?.close(); }
});

test('test helpers preserve cancellation and admission failures', async () => {
  for (const mode of ['cancel', 'throw', 'admission']) {
    const ctx: any = await betterAuth({ secret: 'test-utils-secret-with-at-least-32-characters', logger: { disabled: true }, plugins: [testUtils()],
      user: mode === 'admission' ? { validateUserInfo: () => { throw new Error('must not call'); } } : undefined,
      databaseHooks: { user: { create: { before: () => { if (mode === 'cancel') return false; if (mode === 'throw') throw new Error('before failed'); } } } },
    }).$context;
    const draft = ctx.test.createUser({ email: 'x@example.com' });
    if (mode === 'cancel') expect(await ctx.test.saveUser(draft)).toBeNull();
    else if (mode === 'throw') await expect(ctx.test.saveUser(draft)).rejects.toThrow('before failed');
    else await expect(ctx.test.saveUser(draft)).rejects.toMatchObject({ body: { code: 'validation_context_missing' } });
    expect(await ctx.internalAdapter.findUserById(draft.id)).toBeNull();
  }
});

test('raw test organization deletion commits children before a parent failure', async () => {
  const database = new Database(':memory:');
  const options = { database, secret: 'test-utils-secret-with-at-least-32-characters', logger: { disabled: true }, plugins: [organization(), testUtils()] };
  await (await getMigrations(options)).runMigrations();
  const ctx: any = await betterAuth(options).$context;
  const user = await ctx.test.saveUser(ctx.test.createUser());
  const org = await ctx.test.saveOrganization(ctx.test.createOrganization());
  const member = await ctx.test.addMember({ userId: user.id, organizationId: org.id });
  database.exec("CREATE TRIGGER fail_org_delete BEFORE DELETE ON organization BEGIN SELECT RAISE(FAIL, 'parent failed'); END");
  await expect(ctx.test.deleteOrganization(org.id)).rejects.toThrow('parent failed');
  expect(database.query('SELECT * FROM member WHERE id=?').get(member.id)).toBeNull();
  expect(database.query('SELECT * FROM organization WHERE id=?').get(org.id)).not.toBeNull();
  database.close();
});

for (const databaseEnabled of [false, true]) {
  test(`${databaseEnabled ? "sqlite" : "memory"}: session cancellation and committed after error`, async () => {
    const { context, helpers, database } = await fixture(databaseEnabled, { databaseHooks: { session: { create: {
      before: (session: any) => session.label === "cancel" ? false : undefined,
      after: (session: any) => { if (session.label === "fail-after") throw new Error("after failed"); },
    } } } });
    try {
      const user = await helpers.saveUser(helpers.createUser());
      await expect(helpers.login({userId:user.id, session:{label:"cancel"}})).rejects.toBeInstanceOf(TypeError);
      await expect(helpers.login({userId:user.id, session:{label:"fail-after"}})).rejects.toThrow("after failed");
      const rows = await context.internalAdapter.listSessions(user.id);
      expect(rows).toHaveLength(1); expect(rows[0].label).toBe("fail-after");
    } finally { database?.close(); }
  });
}

test("plugin session fields survive helpers while disabled fields are stripped", async () => {
  const { context, helpers, database } = await fixture(true, { plugins: [organization({teams:{enabled:true}}), testUtils()] });
  try {
    const user = await helpers.saveUser(helpers.createUser());
    const result = await helpers.login({ userId:user.id, session:{activeOrganizationId:"org",activeTeamId:"team"} });
    expect(result.session).toMatchObject({activeOrganizationId:"org",activeTeamId:"team"});
    expect(await context.internalAdapter.findSession(result.token)).toMatchObject({session:{activeOrganizationId:"org",activeTeamId:"team"}});
  } finally { database?.close(); }
});

test("internal user/session helpers inherit transactions; raw organization helpers keep the captured adapter", async () => {
  const { memoryAdapter } = await import("better-auth/adapters/memory");
  const { runWithTransaction } = await import("@better-auth/core/context");
  const calls:string[]=[];
  const memory=memoryAdapter({user:[],session:[],account:[],verification:[],organization:[],member:[],invitation:[]});
  const database=(options:any)=>{
    const adapter:any=memory(options);
    const wrap=(scope:string)=>({...adapter,
      create:(input:any)=>{calls.push(`${scope}:${input.model}`);return adapter.create(input);},
    });
    return {...wrap("outer"),transaction:async(fn:any)=>fn(wrap("tx"))};
  };
  const context:any=await betterAuth({database,baseURL:"https://test.example",secret:"test-utils-secret-at-least-thirty-two-characters",logger:{disabled:true},plugins:[organization(),testUtils()]}).$context;
  await runWithTransaction(context.adapter,async()=>{
    const user=await context.test.saveUser(context.test.createUser());
    await context.test.login({userId:user.id});
    const org=await context.test.saveOrganization(context.test.createOrganization());
    await context.test.addMember({userId:user.id,organizationId:org.id});
  });
  expect(calls).toEqual(["tx:user","tx:session","outer:organization","outer:member"]);
});

test("raw organization metadata keeps adapter input semantics",async()=>{
  for (const databaseEnabled of [false,true]) {
    const {context,helpers,database}=await fixture(databaseEnabled,{plugins:[organization(),testUtils()]});
    try {
      const draft=helpers.createOrganization({metadata:{key:"value"}});
      expect(draft.metadata).toEqual({key:"value"});
      if (databaseEnabled) await expect(helpers.saveOrganization(draft)).rejects.toThrow();
      else expect((await helpers.saveOrganization(draft)).metadata).toEqual({key:"value"});
      for (const metadata of [null,"plain",'{"key":"value"}',"null"]) {
        const saved=await helpers.saveOrganization(helpers.createOrganization({metadata}));
        expect(saved.metadata).toEqual(metadata);
        expect((await context.adapter.findOne({model:"organization",where:[{field:"id",value:saved.id}]})).metadata).toEqual(metadata);
      }
    } finally {database?.close();}
  }
});
