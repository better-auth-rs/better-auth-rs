import { afterAll, expect, test } from "bun:test";
import { createRequire } from "node:module";
import { AsyncLocalStorage } from "node:async_hooks";

const require = createRequire(new URL("../package.json", import.meta.url));
const { trace } = require("@opentelemetry/api");
const { z } = require("zod");
const { betterAuth } = await import(require.resolve("better-auth"));
const { APIError, createAuthEndpoint, createAuthMiddleware } = await import(require.resolve("better-auth/api"));
const { withSpan } = await import(require.resolve("@better-auth/core/instrumentation"));
const { createLogger } = await import(require.resolve("@better-auth/core/env"));

type Recorded = { name: string; attributes: Record<string, unknown>; scope: string; version: string; parent?: string; status?: unknown; exceptions: string[]; ended: number };
const spans: Recorded[] = [];
const active = new AsyncLocalStorage<Recorded>();
trace.setGlobalTracerProvider({
  getTracer(scope: string, version: string) {
    return {
      startActiveSpan(name: string, options: any, callback: any) {
        const record: Recorded = { name, attributes: { ...options.attributes }, scope, version, parent: active.getStore()?.name, exceptions: [], ended: 0 };
        spans.push(record);
        const span = {
          end() { record.ended++; },
          setAttribute(key: string, value: unknown) { record.attributes[key] = value; },
          setStatus(status: unknown) { record.status = status; },
          recordException(error: any) { record.exceptions.push(error.message ?? String(error)); },
        };
        return active.run(record, () => callback(span));
      },
    };
  },
});
afterAll(() => trace.disable());

// Upstream mergeSchema mutates module-level plugin schemas. Restore test overrides before other contract files run.
const { twoFactor, deviceAuthorization, siwe } = await import(require.resolve("better-auth/plugins"));
const { passkey } = await import(require.resolve("@better-auth/passkey"));
const schemaNames = [twoFactor().schema, deviceAuthorization().schema, siwe({verifyMessage: async () => true}).schema, passkey().schema]
  .flatMap(schema => Object.values(schema).map(model => ({model, descriptor: Object.getOwnPropertyDescriptor(model, "modelName")})));
afterAll(() => {
  for (const {model, descriptor} of schemaNames) {
    if (descriptor) Object.defineProperty(model, "modelName", descriptor);
    else delete (model as any).modelName;
  }
});

// The upstream API loads OpenTelemetry lazily; wait for that actual import to finish.
for (let attempt = 0; attempt < 50 && !spans.length; attempt++) {
  await withSpan("warmup", {}, async () => {});
  if (!spans.length) await new Promise(resolve => setTimeout(resolve, 10));
}
expect(spans.length).toBeGreaterThan(0);
spans.length = 0;

const middleware = () => createAuthMiddleware(async () => {});
function build(enabled?: boolean, databaseHooks?: any) {
  return betterAuth({
    secret: "observability-reference-secret-more-than-32-characters",
    baseURL: "http://observability.test",
    logger: { disabled: true },
    experimental: { instrumentation: { enabled } },
    emailAndPassword: { enabled: true },
    hooks: { before: middleware(), after: middleware() },
    databaseHooks,
    plugins: [{
      id: "observe",
      hooks: {
        before: [{ matcher: () => true, handler: middleware() }],
        after: [{ matcher: () => true, handler: middleware() }],
      },
      endpoints: {
        probe: createAuthEndpoint("/probe", { method: "GET", metadata: { operationId: "probeOperation" } }, async (ctx: any) => {
          if (ctx.query?.kind === "ordinary") throw new Error("ordinary failure");
          if (ctx.query?.kind === "api") throw new APIError("BAD_REQUEST", { message: "api failure" });
          if (ctx.query?.kind === "redirect") throw ctx.redirect("/next");
          return ctx.json({ ok: true });
        }),
      },
    }],
  });
}

for (const native of [false, true]) {
  for (const kind of ["success", "api", "ordinary", "redirect"]) {
    test(`${native ? "native" : "HTTP"} spans preserve ${kind} outcome`, async () => {
      const auth = build();
      await auth.$context;
      spans.length = 0;
      let caught: any;
      let result: any;
      try {
        result = native
          ? await (auth.api as any).probe({ query: { kind } })
          : await auth.handler(new Request(`http://observability.test/api/auth/probe?kind=${kind}`));
      } catch (error) { caught = error; }
      if (native) expect(!!caught).toBe(kind !== "success");
      else expect(result.status).toBe({ success: 200, api: 400, ordinary: 500, redirect: 302 }[kind]);
      const outer = spans.find(span => span.name === "GET /probe")!;
      const handler = spans.find(span => span.name === "handler /probe")!;
      expect(outer.attributes).toMatchObject({ "http.route": "/probe", "better_auth.operation_id": "probe" });
      expect(handler.parent).toBe("GET /probe");
      expect(spans.map(span => span.name)).toEqual([
        "GET /probe", "hook before /probe user", "hook before /probe plugin:observe", "handler /probe",
        ...(kind === "ordinary" ? [] : ["hook after /probe user", "hook after /probe plugin:observe"]),
      ]);
      for (const span of spans) {
        expect(span.scope).toBe("better-auth");
        expect(span.version).toBe("1.7.6");
        expect(span.ended).toBe(1);
      }
      const errored = kind === "ordinary" || kind === "api";
      expect(handler.exceptions.length).toBe(errored ? 1 : 0);
      if (errored) expect(handler.status).toEqual({ code: 2, message: `${kind} failure` });
      if (kind === "redirect") {
        expect(handler.status).toEqual({ code: 1 });
        expect(handler.attributes["http.response.status_code"]).toBe(302);
      }
      expect(outer.exceptions.length).toBe(kind === "ordinary" || (native && kind === "api") ? 1 : 0);
      if (native && kind === "redirect") expect(outer.status).toEqual({ code: 1 });
    });
  }
}

test("per-instance disable suppresses endpoint and database spans", async () => {
  const disabled = build(false, { user: { create: { before: async () => {}, after: async () => {} } } });
  await disabled.$context;
  spans.length = 0;
  await disabled.api.signUpEmail({ body: { email: "disabled@example.test", name: "Disabled", password: "Password123!" } });
  expect(spans).toEqual([]);
  const enabled = build(true, { user: { create: { before: async () => {}, after: async () => {} } } });
  await enabled.$context;
  spans.length = 0;
  await enabled.api.signUpEmail({ body: { email: "enabled@example.test", name: "Enabled", password: "Password123!" } });
  const databaseSpans=spans.filter(span=>span.name.startsWith("db "));
  expect(databaseSpans.map(span => span.name)).toEqual(["db findOne user","db create.before user","db create user","db create account","db create session","db create.after user"]);
  expect(databaseSpans.every(span=>span.parent==="handler /sign-up/email")).toBe(true);
  expect(spans.find(span => span.name === "db create user")?.attributes).toEqual({ "db.collection.name": "user", "db.operation.name": "create" });
  expect(spans.find(span => span.name === "db create.before user")?.attributes).toEqual({ "better_auth.hook.type": "create.before", "db.collection.name": "user", "better_auth.context": "user" });
  expect(spans.every(span => span.ended === 1)).toBe(true);
});

test("logger thresholds, disable, raw callback arguments and success mapping", () => {
  for (const threshold of [undefined, "debug", "info", "success", "warn", "error"]) {
    for (const disabled of [false, true]) {
      const events: unknown[] = [];
      const logger = createLogger({ level: threshold, disabled, disableColors: false, log: (...args: unknown[]) => events.push(args) });
      for (const level of ["debug", "info", "success", "warn", "error"]) logger[level]("literal %s", { value: 1 }, "tail");
      const levels = ["debug", "info", "success", "warn", "error"];
      expect(events).toEqual(disabled ? [] : levels.slice(levels.indexOf(threshold ?? "warn")).map(level => [level === "success" ? "info" : level, "literal %s", { value: 1 }, "tail"]));
      expect(logger.level).toBe(threshold ?? "warn");
    }
  }
});

const {createTelemetry}=await import(require.resolve("@better-auth/telemetry"));
test("telemetry defaults off; explicit custom sink supersedes debug and catches rejection",async()=>{
    delete process.env.BETTER_AUTH_TELEMETRY;
    const events:any[]=[];
    const sink={skipTestCheck:true,customTrack:async(event:any)=>{events.push(event)}};
    const disabled=await createTelemetry({baseURL:"http://observability.test"},sink);
    await disabled.publish({type:"probe",payload:{safe:true}});
    expect(events).toEqual([]);
    const enabled=await createTelemetry({baseURL:"http://observability.test",telemetry:{enabled:true,debug:true}},sink);
    await enabled.publish({type:"probe",payload:{safe:true}});
    expect(events.map(e=>e.type)).toEqual(["init","probe"]);
    expect(events[1].payload).toEqual({safe:true});
    expect(events[0].anonymousId).toBe(events[1].anonymousId);
    const rejecting=await createTelemetry({telemetry:{enabled:true}},{skipTestCheck:true,customTrack:async()=>{throw new Error("controlled failure")}});
    await expect(rejecting.publish({type:"probe",payload:{}})).resolves.toBeUndefined();
});

test("global hooks are awaited and execute before the corresponding plugin hooks",async()=>{
    const calls:string[]=[];
    const auth=betterAuth({secret:"observability-reference-secret-more-than-32-characters",baseURL:"http://observability.test",logger:{disabled:true},
        hooks:{before:createAuthMiddleware(async()=>{calls.push("before-user-start");await Promise.resolve();calls.push("before-user-end")}),after:createAuthMiddleware(async()=>{calls.push("after-user-start");await Promise.resolve();calls.push("after-user-end")})},
        plugins:[{id:"observe",hooks:{before:[{matcher:()=>true,handler:createAuthMiddleware(async()=>{calls.push("before-plugin")})}],after:[{matcher:()=>true,handler:createAuthMiddleware(async()=>{calls.push("after-plugin")})}]},endpoints:{probe:createAuthEndpoint("/probe",{method:"GET"},async()=>{calls.push("handler");return {ok:true}})}}],
    });
    expect(await(auth.api as any).probe()).toEqual({ok:true});
    expect(calls).toEqual(["before-user-start","before-user-end","before-plugin","handler","after-user-start","after-user-end","after-plugin"]);
});

test("global before API errors skip later hooks while after API errors continue later hooks",async()=>{
    for(const phase of ["before","after"]){
        const calls:string[]=[];
        const auth=betterAuth({secret:"observability-reference-secret-more-than-32-characters",baseURL:"http://observability.test",logger:{disabled:true},
            hooks:{[phase]:createAuthMiddleware(async()=>{calls.push(`user-${phase}`);await Promise.resolve();throw new APIError("BAD_REQUEST",{message:"global rejection"})})},
            plugins:[{id:"observe",hooks:{before:[{matcher:()=>true,handler:createAuthMiddleware(async()=>{calls.push("before-plugin")})}],after:[{matcher:()=>true,handler:createAuthMiddleware(async()=>{calls.push("after-plugin")})}]},endpoints:{probe:createAuthEndpoint("/probe",{method:"GET"},async()=>{calls.push("handler");return {ok:true}})}}],
        });
        await expect((auth.api as any).probe()).rejects.toMatchObject({body:{message:"global rejection"}});
        expect(calls).toEqual(phase==="before"?["user-before"]:["before-plugin","handler","user-after","after-plugin"]);
    }
});

test("physical collections and logical updates preserve hook and transform boundaries",async()=>{
  const {Database}=await import("bun:sqlite");
  const {getMigrations}=await import(require.resolve("better-auth/db/migration"));
  const db=new Database(":memory:");
  const options={
    secret:"observability-reference-secret-more-than-32-characters",
    baseURL:"http://observability.test",database:db,logger:{disabled:true},
    user:{modelName:"traced_people",additionalFields:{note:{type:"string",required:false,transform:{input:(value:any)=>{if(value==="reject")throw new Error("rejected transform");return value}}}}},
    databaseHooks:{user:{update:{before:async()=>{},after:async()=>{}}}},
  };
  await (await getMigrations(options)).runMigrations();
  const auth=betterAuth(options);
  const context=await auth.$context;
  const first=await context.internalAdapter.createUser({email:"first@example.test",name:"First"});
  const second=await context.internalAdapter.createUser({email:"second@example.test",name:"Second"});
  for(const kind of ["success","missing","duplicate","transform"]){
    spans.length=0;
    let caught:any;
    let result:any;
    try{result=await context.internalAdapter.updateUser(kind==="missing"?"missing":second.id,{name:"Changed",...(kind==="duplicate"?{email:first.email}:{}),...(kind==="transform"?{note:"reject"}:{})})}catch(error){caught=error}
    if(kind==="success")expect(result.name).toBe("Changed");
    else if(kind==="missing")expect(result).toBeNull();
    else expect(caught).toBeDefined();
    expect(spans.map(span=>span.name)).toEqual(kind==="transform"?["db update.before user"]:kind==="duplicate"?["db update.before user","db update traced_people"]:["db update.before user","db update traced_people","db update.after user"]);
    expect(spans.every(span=>span.parent===undefined&&span.ended===1)).toBe(true);
    for(const span of spans){
      const raw=span.name==="db update traced_people";
      expect(span.attributes["db.collection.name"]).toBe(raw?"traced_people":"user");
      expect(span.exceptions.length).toBe(Number(raw&&kind==="duplicate"));
      if(raw&&kind==="duplicate")expect((span.status as any).code).toBe(2);
      if(raw&&kind==="missing")expect(span.status).toBeUndefined();
    }
  }
  expect((await context.internalAdapter.findUserById(second.id)).email).toBe("second@example.test");
  db.close();
});

test("global patches stay invisible to later before hooks; validation errors belong to handler spans", async () => {
  for (const invalid of [false, true]) {
    const events: unknown[] = [];
    const auth = betterAuth({
      secret: "observability-reference-secret-more-than-32-characters",
      baseURL: "http://observability.test", logger: { disabled: true },
      hooks: {
        before: createAuthMiddleware(async (ctx: any) => {
          events.push(["user-before", ctx.body]);
          return { context: { body: { value: invalid ? 7 : "user", user: true } } };
        }),
        after: createAuthMiddleware(async (ctx: any) => { events.push(["user-after", ctx.body]); }),
      },
      plugins: [{ id: "projection", hooks: { before: [{ matcher: () => true, handler: createAuthMiddleware(async (ctx: any) => {
        events.push(["plugin-before", ctx.body]);
        return { context: { body: { plugin: true } } };
      }) }] }, endpoints: { projection: createAuthEndpoint("/projection", {
        method: "POST", body: z.object({ value: z.string(), user: z.boolean(), plugin: z.boolean() }),
      }, async (ctx: any) => { events.push(["handler", ctx.body]); return ctx.body; }) } }],
    });
    await auth.$context;
    spans.length = 0;
    const raw = { value: "raw", extra: true };
    const response = await (auth.api as any).projection({ body: raw }).then(
      (value: unknown) => ({ value }), (error: any) => ({ status: error.statusCode }),
    );
    expect(response).toEqual(invalid ? { status: 400 } : { value: { value: "user", user: true, plugin: true } });
    expect(events).toEqual([
      ["user-before", raw], ["plugin-before", raw],
      ...(!invalid ? [["handler", { value: "user", user: true, plugin: true }]] : []),
      ["user-after", { value: invalid ? 7 : "user", extra: true, user: true, plugin: true }],
    ]);
    expect(spans.find(span => span.name === "handler /projection")?.exceptions.length).toBe(invalid ? 1 : 0);
  }
});

for (const backend of ["memory", "sqlite"]) {
  test(`${backend} plugin adapters trace logical operations and null updates`, async () => {
    const {passkey}=await import(require.resolve("@better-auth/passkey"));
    const {jwt,siwe}=await import(require.resolve("better-auth/plugins"));
    const {Database}=await import("bun:sqlite");
    const {getMigrations}=await import(require.resolve("better-auth/db/migration"));
    const db=backend==="sqlite"?new Database(":memory:"):undefined;
    const collection=backend==="sqlite"?"traced_authenticators":"passkey";
    const walletCollection=backend==="sqlite"?"wallet_address":"walletAddress";
    const options={secret:"observability-reference-secret-more-than-32-characters",baseURL:"http://observability.test",database:db,logger:{disabled:true},plugins:[
      passkey({schema:{passkey:{modelName:collection}}}),jwt(),siwe({verifyMessage:async()=>true,schema:{walletAddress:{modelName:walletCollection}}})
    ]};
    if(db)await(await getMigrations(options)).runMigrations();
    const ctx=await betterAuth(options).$context;
    spans.length=0;
    const row=await ctx.adapter.create({model:"passkey",data:{publicKey:"public",userId:"owner",credentialID:"credential",counter:0,deviceType:"singleDevice",backedUp:false}});
    expect((await ctx.adapter.findOne({model:"passkey",where:[{field:"credentialID",value:"credential"}]})).id).toBe(row.id);
    expect((await ctx.adapter.update({model:"passkey",where:[{field:"id",value:row.id}],update:{name:"Renamed"}})).name).toBe("Renamed");
    expect(await ctx.adapter.update({model:"passkey",where:[{field:"id",value:"missing"}],update:{name:"Ignored"}})).toBeNull();
    expect((await ctx.adapter.findMany({model:"passkey",where:[{field:"userId",value:"owner"}]})).length).toBe(1);
    await ctx.adapter.delete({model:"passkey",where:[{field:"id",value:row.id}]});
    expect((await ctx.adapter.findMany({model:"passkey",where:[{field:"userId",value:"owner"}]})).length).toBe(0);
    const key=await ctx.adapter.create({model:"jwks",data:{publicKey:"public",privateKey:"private",createdAt:new Date()}});
    expect((await ctx.adapter.findOne({model:"jwks",where:[{field:"id",value:key.id}]})).id).toBe(key.id);
    expect((await ctx.adapter.findMany({model:"jwks"})).length).toBe(1);
    const wallet=await ctx.adapter.create({model:"walletAddress",data:{userId:"owner",address:"0x123",chainId:1,isPrimary:true,createdAt:new Date()}});
    expect((await ctx.adapter.findOne({model:"walletAddress",where:[{field:"address",value:"0x123"},{field:"chainId",value:1}]})).id).toBe(wallet.id);
    const operations=[...['create','findOne','update','update','findMany','delete','findMany'].map(op=>[op,collection]),...['create','findOne','findMany'].map(op=>[op,'jwks']),...['create','findOne'].map(op=>[op,walletCollection])];
    expect(spans.map(span=>span.name)).toEqual(operations.map(([op,model])=>`db ${op} ${model}`));
    for(let index=0;index<spans.length;index++){
      expect(spans[index].attributes).toEqual({'db.operation.name':operations[index][0],'db.collection.name':operations[index][1]});
      expect(spans[index].exceptions).toEqual([]);
      expect(spans[index].status).toBeUndefined();
      expect(spans[index].ended).toBe(1);
    }
    db?.close();
  });
}

for (const backend of ["memory", "sqlite"]) {
  test(`${backend} two-factor lockout traces actual increment branches`, async () => {
    const {twoFactor}=await import(require.resolve("better-auth/plugins"));
    const {recordTwoFactorFailure, resetTwoFactorFailures, assertTwoFactorNotLocked}=await import(new URL("./two-factor/verify-two-factor.mjs", `file://${require.resolve("better-auth/plugins")}`).href);
    const {Database}=await import("bun:sqlite");
    const {getMigrations}=await import(require.resolve("better-auth/db/migration"));
    const db=backend==="sqlite"?new Database(":memory:"):undefined;
    const collection=backend==="sqlite"?"two_factor":"twoFactor";
    const options={secret:"observability-reference-secret-more-than-32-characters",baseURL:"http://observability.test",database:db,logger:{disabled:true},plugins:[twoFactor({accountLockout:{maxFailedAttempts:2},schema:{twoFactor:{modelName:collection}}})]};
    if(db)await(await getMigrations(options)).runMigrations();
    const ctx={context:await betterAuth(options).$context};
    const factor=await ctx.context.adapter.create({model:"twoFactor",data:{userId:"owner",secret:"secret",backupCodes:"codes",verified:true}});
    const trace=async(action:()=>Promise<unknown>, expected:string[])=>{
      spans.length=0;
      await action();
      expect(spans.map(span=>span.name)).toEqual(expected.map(operation=>`db ${operation} ${collection}`));
      for (const span of spans) {
        expect(span.ended).toBe(1);
        expect(span.exceptions).toEqual([]);
        expect(span.status).toBeUndefined();
        expect(span.attributes["db.collection.name"]).toBe(collection);
      }
    };
    await trace(()=>recordTwoFactorFailure(ctx,"twoFactor",factor),["incrementOne"]);
    await trace(()=>recordTwoFactorFailure(ctx,"twoFactor",factor),["incrementOne","incrementOne"]);
    const locked=await ctx.context.adapter.findOne({model:"twoFactor",where:[{field:"id",value:factor.id}]});
    expect(locked.failedVerificationCount).toBe(2);
    expect(locked.lockedUntil).not.toBeNull();
    await trace(()=>resetTwoFactorFailures(ctx,"twoFactor",factor),["update"]);
    await ctx.context.adapter.update({model:"twoFactor",where:[{field:"id",value:factor.id}],update:{lockedUntil:new Date(0),failedVerificationCount:1}});
    await trace(()=>assertTwoFactorNotLocked(ctx,"twoFactor",{...factor,lockedUntil:new Date(0)}),["incrementOne"]);
    const cleared=await ctx.context.adapter.findOne({model:"twoFactor",where:[{field:"id",value:factor.id}]});
    expect(cleared.failedVerificationCount).toBe(0);
    expect(cleared.lockedUntil).toBeNull();
    db?.close();
  });
}

for (const backend of ["memory", "sqlite"]) {
  test(`${backend} device claims trace guards without marking misses as errors`, async () => {
    const {deviceAuthorization}=await import(require.resolve("better-auth/plugins"));
    const {Database}=await import("bun:sqlite");
    const {getMigrations}=await import(require.resolve("better-auth/db/migration"));
    const db=backend==="sqlite"?new Database(":memory:"):undefined;
    const collection=backend==="sqlite"?"device_code":"deviceCode";
    const options={secret:"observability-reference-secret-more-than-32-characters",baseURL:"http://observability.test",database:db,logger:{disabled:true},plugins:[deviceAuthorization({schema:{deviceCode:{modelName:collection}}})]};
    if(db)await(await getMigrations(options)).runMigrations();
    const ctx=await betterAuth(options).$context;
    spans.length=0;
    const code=await ctx.adapter.create({model:"deviceCode",data:{deviceCode:"device-secret",userCode:"ABCD2345",expiresAt:new Date(Date.now()+600000),status:"pending",pollingInterval:5000,clientId:"client"}});
    expect((await ctx.adapter.findOne({model:"deviceCode",where:[{field:"userCode",value:"ABCD2345"}]})).id).toBe(code.id);
    const claim=(userId:string)=>ctx.adapter.incrementOne({model:"deviceCode",where:[{field:"id",value:code.id},{field:"status",value:"pending"},{field:"userId",value:null}],increment:{},set:{userId}});
    expect((await claim("owner")).userId).toBe("owner");
    expect(await claim("other")).toBeNull();
    const update=(status:string)=>ctx.adapter.update({model:"deviceCode",where:[{field:"id",value:code.id},{field:"status",value:"pending"}],update:{status}});
    expect((await update("approved")).status).toBe("approved");
    const approved=await ctx.adapter.findOne({model:"deviceCode",where:[{field:"deviceCode",value:"device-secret"}]});
    expect(approved.userId).toBe("owner");
    expect(approved.status).toBe("approved");
    expect(await update("denied")).toBeNull();
    expect((await ctx.adapter.update({model:"deviceCode",where:[{field:"id",value:code.id}],update:{lastPolledAt:new Date()}})).lastPolledAt).toBeInstanceOf(Date);
    expect(await ctx.adapter.update({model:"deviceCode",where:[{field:"id",value:"missing"}],update:{status:"denied"}})).toBeNull();
    await ctx.adapter.delete({model:"deviceCode",where:[{field:"id",value:code.id},{field:"status",value:"pending"}]});
    await ctx.adapter.delete({model:"deviceCode",where:[{field:"id",value:code.id},{field:"status",value:"approved"}]});
    expect(await ctx.adapter.findOne({model:"deviceCode",where:[{field:"deviceCode",value:"device-secret"}]})).toBeNull();
    await ctx.adapter.delete({model:"deviceCode",where:[{field:"id",value:code.id}]});
    const operations=["create","findOne","incrementOne","incrementOne","update","findOne","update","update","update","delete","delete","findOne","delete"];
    expect(spans.map(span=>span.name)).toEqual(operations.map(op=>`db ${op} ${collection}`));
    for (const span of spans) {
      expect(span.ended).toBe(1);
      expect(span.exceptions).toEqual([]);
      expect(span.status).toBeUndefined();
      expect(span.attributes["db.collection.name"]).toBe(collection);
    }
    db?.close();
  });
}
for (const backend of ["memory", "sqlite"]) {
  test(`${backend} API key usage traces quota, rate and final writes separately`, async () => {
    const {apiKey}=await import(require.resolve("@better-auth/api-key"));
    const {Database}=await import("bun:sqlite");
    const {getMigrations}=await import(require.resolve("better-auth/db/migration"));
    const db=backend==="sqlite"?new Database(":memory:"):undefined;
    const options={secret:"observability-reference-secret-more-than-32-characters",baseURL:"http://observability.test",database:db,logger:{disabled:true},plugins:[apiKey({disableKeyHashing:true,deferUpdates:false})]};
    if(db)await(await getMigrations(options)).runMigrations();
    const auth=betterAuth(options);
    const ctx=await auth.$context;
    const row=await ctx.adapter.create({model:"apikey",data:{key:"secret-key",referenceId:"owner",configId:"default",enabled:true,remaining:3,refillAmount:null,refillInterval:null,lastRefillAt:null,rateLimitEnabled:true,rateLimitTimeWindow:60000,rateLimitMax:1,requestCount:0,lastRequest:null,createdAt:new Date(0),updatedAt:new Date(0)}});
    const verify=async(expected:string[])=>{
      spans.length=0;
      const result=await auth.api.verifyApiKey({body:{key:"secret-key"}});
      expect(spans.filter(span=>span.name.startsWith("db ")).map(span=>span.name)).toEqual(expected.map(op=>`db ${op} apikey`));
      return result;
    };
    const allowed=await verify(["findOne","incrementOne","incrementOne","update"]);
    expect(allowed.valid).toBe(true);
    expect(allowed.key.remaining).toBe(2);
    expect(allowed.key.requestCount).toBe(1);
    for(const remaining of [1,0]) {
      const denied=await verify(["findOne","incrementOne"]);
      expect(denied.valid).toBe(false);
      expect(denied.error.code).toBe("RATE_LIMITED");
      const stored=await ctx.adapter.findOne({model:"apikey",where:[{field:"id",value:row.id}]});
      expect(stored.remaining).toBe(remaining);
      expect(stored.requestCount).toBe(1);
      expect(stored.lastRequest).toEqual(allowed.key.lastRequest);
      expect(stored.updatedAt).toEqual(allowed.key.updatedAt);
    }
    const exhausted=await verify(["findOne","delete"]);
    expect(exhausted.valid).toBe(false);
    expect(exhausted.error.code).toBe("USAGE_EXCEEDED");
    expect(await ctx.adapter.findOne({model:"apikey",where:[{field:"id",value:row.id}]})).toBeNull();
    db?.close();
  });
}

for (const failedField of ["remaining", "requestCount", "updatedAt"]) {
  test(`sqlite API key ${failedField} failure preserves earlier adapter writes`, async () => {
    const {apiKey}=await import(require.resolve("@better-auth/api-key"));
    const {Database}=await import("bun:sqlite");
    const {getMigrations}=await import(require.resolve("better-auth/db/migration"));
    const db=new Database(":memory:");
    const options={secret:"observability-reference-secret-more-than-32-characters",baseURL:"http://observability.test",database:db,logger:{disabled:true},plugins:[apiKey({disableKeyHashing:true,deferUpdates:false})]};
    await(await getMigrations(options)).runMigrations();
    const auth=betterAuth(options);
    const ctx=await auth.$context;
    const row=await ctx.adapter.create({model:"apikey",data:{key:"secret-key",referenceId:"owner",configId:"default",enabled:true,remaining:3,refillAmount:null,refillInterval:null,lastRefillAt:null,rateLimitEnabled:true,rateLimitTimeWindow:60000,rateLimitMax:1,requestCount:0,lastRequest:null,createdAt:new Date(0),updatedAt:new Date(0)}});
    db.exec(`CREATE TRIGGER reject_write BEFORE UPDATE OF "${failedField}" ON "apikey" BEGIN SELECT RAISE(ABORT, 'controlled storage failure'); END`);
    spans.length=0;
    const result=await auth.api.verifyApiKey({body:{key:"secret-key"}});
    expect(result.valid).toBe(false);
    expect(result.error.code).toBe("INVALID_API_KEY");
    const operations=failedField==="remaining"?["findOne","incrementOne"]:failedField==="requestCount"?["findOne","incrementOne","incrementOne"]:["findOne","incrementOne","incrementOne","update"];
    const recorded=spans.filter(span=>span.name.startsWith("db "));
    expect(recorded.map(span=>span.name)).toEqual(operations.map(op=>`db ${op} apikey`));
    expect(recorded.at(-1)!.status).toEqual({code:2,message:"controlled storage failure"});
    expect(recorded.at(-1)!.exceptions).toEqual(["controlled storage failure"]);
    const stored=await ctx.adapter.findOne({model:"apikey",where:[{field:"id",value:row.id}]});
    expect(stored.remaining).toBe(failedField==="remaining"?3:2);
    expect(stored.requestCount).toBe(failedField==="updatedAt"?1:0);
    expect(stored.lastRequest===null).toBe(failedField!=="updatedAt");
    expect(stored.updatedAt).toEqual(new Date(0));
    db.close();
  });
}
for (const backend of ["memory", "sqlite"]) {
  test(`${backend} API key list applies database default before public pagination and ignores raw count`, async () => {
    const {apiKey}=await import(require.resolve("@better-auth/api-key"));
    const {Database}=await import("bun:sqlite");
    const {getMigrations}=await import(require.resolve("better-auth/db/migration"));
    const db=backend==="sqlite"?new Database(":memory:"):undefined;
    const options={secret:"observability-reference-secret-more-than-32-characters",baseURL:"http://observability.test",database:db,logger:{disabled:true},emailAndPassword:{enabled:true},advanced:{database:{defaultFindManyLimit:2}},plugins:[apiKey({disableKeyHashing:true,deferUpdates:false})]};
    if(db)await(await getMigrations(options)).runMigrations();
    const auth=betterAuth(options);
    const ctx=await auth.$context;
    const signup=await auth.api.signUpEmail({body:{email:"list@example.com",name:"List",password:"password-123456"},returnHeaders:true});
    const headers=new Headers({cookie:signup.headers.getSetCookie().map((value:string)=>value.split(";")[0]).join("; ")});
    for(const [index,name] of ["D","A","E","C","B"].entries()) {
      await ctx.adapter.create({model:"apikey",data:{name,key:`secret-${index}`,referenceId:signup.response.user.id,configId:"default",createdAt:new Date(index),updatedAt:new Date(index)}});
    }
    expect(await ctx.adapter.count({model:"apikey"})).toBe(5);
    spans.length=0;
    const result=await auth.api.listApiKeys({headers,query:{sortBy:"name",sortDirection:"desc",offset:1,limit:1}});
    expect(result.apiKeys.map((key:any)=>key.name)).toEqual(["D"]);
    expect(result.total).toBe(2);
    expect(result.limit).toBe(1);
    expect(result.offset).toBe(1);
    const operations=spans.filter(span=>span.attributes["db.collection.name"]==="apikey").map(span=>span.attributes["db.operation.name"]);
    expect(operations.slice(0,2)).toEqual(["findMany","count"]);
    db?.close();
  });
}
test("API key list preserves count failures and cached lists skip the database default", async () => {
  const {apiKey}=await import(require.resolve("@better-auth/api-key"));
  const values=new Map<string,string>();
  const customStorage={get:async(key:string)=>values.get(key)??null,set:async(key:string,value:string)=>{values.set(key,value)},delete:async(key:string)=>{values.delete(key)}};
  const auth=betterAuth({secret:"observability-reference-secret-more-than-32-characters",baseURL:"http://observability.test",logger:{disabled:true},emailAndPassword:{enabled:true},advanced:{database:{defaultFindManyLimit:2}},plugins:[apiKey({storage:"secondary-storage",customStorage,fallbackToDatabase:true,disableKeyHashing:true,deferUpdates:false})]});
  const ctx=await auth.$context;
  const signup=await auth.api.signUpEmail({body:{email:"cached-list@example.com",name:"List",password:"password-123456"},returnHeaders:true});
  const headers=new Headers({cookie:signup.headers.getSetCookie().map((value:string)=>value.split(";")[0]).join("; ")});
  const keys=[];
  for(const [index,name] of ["D","A","E","C","B"].entries()) {
    keys.push(await ctx.adapter.create({model:"apikey",data:{name,key:`cached-${index}`,referenceId:signup.response.user.id,configId:"default",createdAt:new Date(index),updatedAt:new Date(index)}}));
  }
  const query={sortBy:"name",sortDirection:"desc",offset:1,limit:1};
  spans.length=0;
  const fallback=await auth.api.listApiKeys({headers,query});
  expect(fallback.total).toBe(2);
  expect(fallback.apiKeys.map((key:any)=>key.name)).toEqual(["D"]);
  expect(spans.filter(span=>span.attributes["db.collection.name"]==="apikey").map(span=>span.attributes["db.operation.name"]).slice(0,2)).toEqual(["findMany","count"]);
  ctx.adapter.count=async()=>{throw new Error("controlled count failure")};
  spans.length=0;
  const cached=await auth.api.listApiKeys({headers,query});
  expect(cached.total).toBe(2);
  expect(cached.apiKeys.map((key:any)=>key.name)).toEqual(["D"]);
  expect(spans.filter(span=>span.attributes["db.collection.name"]==="apikey").map(span=>span.attributes["db.operation.name"]).filter(operation=>operation==="findMany"||operation==="count")).toEqual([]);
  for(const key of keys)values.set(`api-key:by-id:${key.id}`,JSON.stringify(key));
  values.set(`api-key:by-ref:${signup.response.user.id}`,JSON.stringify(keys.map(key=>key.id)));
  const allCached=await auth.api.listApiKeys({headers,query});
  expect(allCached.total).toBe(5);
  expect(allCached.apiKeys.map((key:any)=>key.name)).toEqual(["D"]);
  values.clear();
  await expect(auth.api.listApiKeys({headers,query})).rejects.toThrow("controlled count failure");
});
