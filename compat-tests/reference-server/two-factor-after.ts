import { betterAuth } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { phoneNumber, twoFactor, username } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { Database } from "bun:sqlite";

export async function createTwoFactorAfterFixture(profile: string, baseURL: string) {
  let active = false, mode = "normal", otp = "";
  let events: any[] = [];
  const email = "factor@example.test", password = "password123";
  const target = (path: string) => ["/sign-in/email", "/sign-in/username", "/sign-in/phone-number"].includes(path);
  const shape = (value: any) => value?.name === "APIError" ? {apiError:{status:value.statusCode,body:value.body}} : value ? { ...value, ...(value.token ? { token: true } : {}), ...(value.user ? { user: { email: value.user.email, twoFactorEnabled: value.user.twoFactorEnabled } } : {}) } : value;
  const snapshot = async (phase: string, ctx: any) => {
    if (!active || !target(ctx.path)) return;
    events.push({ phase, returned: shape(ctx.context.returned), newSession: !!ctx.context.newSession, sessions: await ctx.context.adapter.count({ model: "session" }), proofs: await ctx.context.adapter.count({ model: "verification" }) });
  };
  const observer = (phase: string) => ({ id: phase, hooks: { after: [{ matcher: (ctx: any) => target(ctx.path), handler: createAuthMiddleware(async ctx => snapshot(phase, ctx)) }] } });
  const options: any = {
    baseURL, secret: "two-factor-after-fixture-secret-at-least-32", logger: { disabled: true }, rateLimit: { enabled: false },
    database: profile.endsWith("sqlite") ? new Database(":memory:") : undefined,
    emailAndPassword: { enabled: true, password: { hash: async (value: string) => `fixture:${value}`, verify: async ({ hash, password }: any) => hash === `fixture:${password}` } },
    databaseHooks: {
      session: {
        create: { after: async () => { if (active) events.push({phase:"session-created"}); } },
        delete: {
          before: async () => { if (active) { events.push({phase:"session-delete-before"}); if (mode === "delete-error") throw new Error("session deletion rejected"); } },
          after: async () => { if (active) events.push({phase:"session-delete-after"}); },
        },
      },
      verification: { create: { before: async (data: any) => { if (active && data.identifier.startsWith("2fa-")) { events.push({phase:"proof-create", attempts:data.identifier.startsWith("2fa-attempts-")}); if (mode === "proof-error") throw new Error("challenge creation rejected"); } } } },
    },
    hooks: { after: createAuthMiddleware(async ctx => {
      if (!active || !target(ctx.path)) return;
      await snapshot("user-after", ctx);
      if (mode === "replace") return ctx.json({ custom: true });
      if (mode === "api-error") throw new APIError("BAD_REQUEST", { code: "USER_AFTER_ERROR", message: "user after rejected" });
      if (mode === "ordinary-error") throw new Error("user after failed");
      if (mode === "clear") ctx.context.setNewSession(null);
      if (mode === "cookies") {
        ctx.setCookie("better-auth.session_data.0", "pending-chunk");
        ctx.setCookie("better-auth.dont_remember", "keep-marker");
      }
    }) },
    plugins: [username(), phoneNumber(), observer("plugin-before-2fa"), twoFactor({otpOptions:{sendOTP:async ({otp:code}:any)=>{otp=code;}}}), observer("plugin-after-2fa")],
  };
  if (options.database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context = await auth.$context;
  const created = await auth.api.signUpEmail({body:{email,password,name:"Factor",username:"factor"}} as any);
  await context.adapter.update({model:"user",where:[{field:"id",value:created.user.id}],update:{twoFactorEnabled:true,phoneNumber:"+15551230000",phoneNumberVerified:true}});
  const cookies = (headers: Headers) => headers.getSetCookie().map(line => {
    const pair = line.split(";")[0]; const index=pair.indexOf("=");
    return {name:pair.slice(0,index),empty:pair.slice(index+1)==="",clear:/max-age=0(?:;|$)/i.test(line)};
  });
  return {handle:async(request:Request):Promise<Response>=>{
    const path=new URL(request.url).pathname;
    if(path==="/health"||path==="/__health")return Response.json({status:"ok"});
    if(path==="/__test/reset-state")return Response.json({success:true});
    if(path!=="/__test/two-factor-after")return auth.handler(request);
    const input=await request.json();
    if(input.action==="state")return Response.json({events,otp,sessions:await context.adapter.count({model:"session"}),proofs:await context.adapter.count({model:"verification"})});
    active=false;
    if(input.clear!==false){await context.adapter.deleteMany({model:"session",where:[]});await context.adapter.deleteMany({model:"verification",where:[]});}
    events=[];mode=input.mode??"normal";active=true;
    const kind=input.kind??"email";
    const route=kind==="phone"?"/sign-in/phone-number":`/sign-in/${kind}`;
    const body={password,rememberMe:false,...(kind==="email"?{email}:kind==="username"?{username:"factor"}:{phoneNumber:"+15551230000"})};
    const headers:any={"content-type":"application/json",origin:baseURL};if(input.cookie)headers.cookie=input.cookie;
    let result:any;
    try {
      if(input.native){
        const operation=kind==="phone"?"signInPhoneNumber":kind==="username"?"signInUsername":"signInEmail";
        const native=await(auth.api as any)[operation]({body,headers:new Headers(headers),returnHeaders:true});
        result={status:200,body:shape(native.response),cookies:cookies(native.headers)};
      } else {
        const response=await auth.handler(new Request(baseURL+"/api/auth"+route,{method:"POST",headers,body:JSON.stringify(body)}));
        const text=await response.text();result={status:response.status,body:text?shape(JSON.parse(text)):null,cookies:cookies(response.headers)};
      }
    }catch(error:any){result={error:{ordinary:!error.body,message:error.body?.message??error.message,code:error.body?.code??null}};}
    return Response.json({...result,events,sessions:await context.adapter.count({model:"session"}),proofs:await context.adapter.count({model:"verification"})});
  }};
}
