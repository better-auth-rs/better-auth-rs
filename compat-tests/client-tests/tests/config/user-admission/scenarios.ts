import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
async function control(ctx:Context,body:any={}) {
 const response=await fetch(`${ctx.baseURL}/__test/user-admission`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
 expect(response.status).toBe(200);return response.json();
}
function post(ctx:Context,path:string,json:unknown){return ctx.rawRequest({path:`/api/auth${path}`,method:"POST",json,headers:{"x-admission-tag":"application-policy"}});}
export function admissionScenarios(protectedSignup:boolean) {
 compatScenario("admission rejects new users before persistence and masks callback exceptions",async ctx=>{
  const email=ctx.uniqueEmail("admission-denied");const input={email,name:"Admission User",password:"Password123!",customBody:"passthrough"};
  await control(ctx,{mode:"deny"});
  const denied=await post(ctx,"/sign-up/email",input);
  expect(denied.status).toBe(protectedSignup?200:403);
  if(protectedSignup)expect((denied.body as any).token).toBeNull();
  else expect(denied.body).toEqual({code:"application_denied",message:"Application denied user"});
  const before=await control(ctx,{email});expect(before.exists).toBe(false);expect(before.accounts).toEqual([]);
  expect(before.events).toHaveLength(1);expect(before.events[0]).toMatchObject({source:{method:"email-password",action:"create-user"},hasId:false,hasCreatedAt:true,hasUpdatedAt:true,existing:false,path:"/sign-up/email",tag:"application-policy",customBody:"passthrough",role:null});
  await control(ctx,{mode:"throw",clear:true});
  const thrown=await post(ctx,"/sign-up/email",input);expect(thrown.status).toBe(protectedSignup?200:403);
  if(!protectedSignup)expect(thrown.body).toEqual({code:"validation_failed",message:"User validation failed"});
  expect((await control(ctx,{email})).exists).toBe(false);
  await control(ctx,{mode:"empty",clear:true});
  const accepted=await post(ctx,"/sign-up/email",input);expect(accepted.status,JSON.stringify(accepted.body)).toBe(200);
  await control(ctx,{mode:"deny",clear:true});
  const login=await ctx.actor("returning").client.signIn.email({email,password:input.password});expect(login.error).toBeNull();
  expect((await control(ctx)).events).toEqual([]);
  return {deniedStatus:denied.status,denied:protectedSignup?null:denied.body,before,thrownStatus:thrown.status,thrown:protectedSignup?null:thrown.body,acceptedStatus:accepted.status,loginStatus:login.error?.status??200};
 });
 if(protectedSignup)return;
 compatScenario("admission executes inside the creation transaction and rolls back callback writes",async ctx=>{
  const email=ctx.uniqueEmail("admission-rollback");
  await control(ctx,{mode:"rollback"});
  const rejected=await post(ctx,"/sign-up/email",{email,name:"Rejected",password:"Password123!"});
  expect(rejected.status).toBe(403);
  const snapshot=await control(ctx,{email});expect(snapshot.exists).toBe(false);expect(snapshot.auditExists).toBe(false);
  await control(ctx,{mode:"allow",clear:true});
  const accepted=await post(ctx,"/sign-up/email",{email,name:"Accepted",password:"Password123!"});expect(accepted.status).toBe(200);
  return {rejected,snapshot,acceptedStatus:accepted.status};
 });
 compatScenario("OTP phone anonymous magic-link and admin registration report their real admission source",async ctx=>{
  const owner=ctx.uniqueEmail("admission-admin");
  expect((await post(ctx,"/sign-up/email",{email:owner,name:"Admin",password:"Password123!"})).status).toBe(200);
  await control(ctx,{email:owner,promote:true,mode:"deny",clear:true});
  const adminEmail=ctx.uniqueEmail("admission-created");
  const admin=await post(ctx,"/admin/create-user",{email:adminEmail,name:"Created",password:"Password123!"});expect(admin.status).toBe(403);
  expect((await control(ctx)).events[0]).toMatchObject({source:{method:"admin",action:"create-user"},sessionEmail:owner,role:"user"});
  await ctx.actor().client.signOut();
  const email=ctx.uniqueEmail("admission-otp");
  expect((await post(ctx,"/email-otp/send-verification-otp",{email,type:"sign-in"})).status).toBe(200);
  const otp=await post(ctx,"/sign-in/email-otp",{email,otp:"123456",name:"OTP User",customBody:"kept"});expect(otp.status).toBe(403);
  const otpReplay=await post(ctx,"/sign-in/email-otp",{email,otp:"123456"});expect(otpReplay.status).toBe(400);
  const phone=await post(ctx,"/phone-number/verify",{phoneNumber:"+15551234751",code:"246810"});expect(phone.status).toBe(403);
  const anonymous=await post(ctx,"/sign-in/anonymous",{});expect(anonymous.status).toBe(403);
  const magicEmail=ctx.uniqueEmail("admission-magic");
  expect((await post(ctx,"/sign-in/magic-link",{email:magicEmail,name:"Magic",callbackURL:"/done"})).status).toBe(200);
  const sent=await control(ctx);const magicURL=new URL(sent.magicURL);
  const magic=await ctx.rawRequest({path:magicURL.pathname+magicURL.search,redirect:"manual"});expect(magic.status).toBe(302);
  const destination=new URL(magic.location!,ctx.baseURL);expect(destination.searchParams.get("error")).toBe("application_denied");expect(destination.searchParams.get("error_description")).toBe("Application denied user");
  const snapshot=await control(ctx,{email});expect(snapshot.exists).toBe(false);
  expect(snapshot.events.map((event:any)=>event.source.method)).toEqual(["admin","email-otp","phone-number","anonymous","magic-link"]);
  const events=snapshot.events.map((event:any)=>({...event,email:event.source.method==="anonymous"?"<generated>":event.email}));
  return {admin,otp,otpReplay,phone,anonymous,magic:{status:magic.status,error:destination.searchParams.get("error"),message:destination.searchParams.get("error_description")},events};
 });
 compatScenario("OAuth admission preserves raw profile and rejects before account token updates",async ctx=>{
  const email=ctx.uniqueEmail("admission-oauth");const sub=ctx.uniqueToken("admission-sub");
  await ctx.setSocialProfile({email,sub,name:"Provider User",image:"https://example.com/profile.png",emailVerified:true,idTokenValid:true});
  await control(ctx,{mode:"rollback"});
  const denied=await post(ctx,"/sign-in/social",{provider:"google",idToken:{token:"fixture-id-token",accessToken:"first-token"}});expect(denied.status).toBe(403);
  const absent=await control(ctx,{email});expect(absent.exists).toBe(false);expect(absent.auditExists).toBe(false);
  expect(absent.events[0]).toMatchObject({source:{action:"create-user",method:"oauth",oauth:{providerId:"google",profile:{sub,email,email_verified:true}}},hasId:false,hasCreatedAt:true});
  await control(ctx,{mode:"allow",clear:true});
  const initial=await post(ctx,"/sign-in/social",{provider:"google",idToken:{token:"fixture-id-token",accessToken:"first-token"}});expect(initial.status).toBe(200);
  await ctx.actor().client.signOut();
  await ctx.setSocialProfile({email,sub,name:"Changed Provider Name",image:"https://example.com/profile.png",emailVerified:true,idTokenValid:true});
  await control(ctx,{mode:"deny",clear:true});
  const returning=await post(ctx,"/sign-in/social",{provider:"google",idToken:{token:"fixture-id-token",accessToken:"replacement-token"}});expect(returning.status).toBe(403);
  const persisted=await control(ctx,{email});expect(persisted.accounts).toEqual([{providerId:"google",accessToken:"first-token"}]);
  expect(persisted.events[0]).toMatchObject({name:"Changed Provider Name",source:{action:"sign-in",method:"oauth"},hasId:true,hasCreatedAt:false,existing:true});
  return {denied,absent,initialStatus:initial.status,returning,persisted};
 });
 compatScenario("OAuth implicit and redirect account linking run admission while direct id-token linking does not",async ctx=>{
  const email=ctx.uniqueEmail("admission-link");const sub=ctx.uniqueToken("admission-link-sub");
  expect((await post(ctx,"/sign-up/email",{email,name:"Credential",password:"Password123!"})).status).toBe(200);
  await control(ctx,{email,promote:true,mode:"deny",clear:true});
  await ctx.setSocialProfile({email,sub,name:"Link Provider",image:"https://example.com/link.png",emailVerified:true,idTokenValid:true});
  const implicit=await post(ctx,"/sign-in/social",{provider:"google",idToken:{token:"fixture-id-token"}});expect(implicit.status).toBe(403);
  const before=await control(ctx,{email});expect(before.accounts.map((a:any)=>a.providerId)).toEqual(["credential"]);expect(before.events[0].source.action).toBe("link-account");
  await control(ctx,{clear:true});
  const link=await ctx.actor().client.linkSocial({provider:"google",callbackURL:"/settings"});expect(link.error).toBeNull();
  const state=new URL(link.data!.url!).searchParams.get("state")!;
  const callback=await ctx.rawRequest({path:`/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state)}`,redirect:"manual"});expect(callback.status).toBe(302);
  const location=new URL(callback.location!,ctx.baseURL);expect(location.searchParams.get("error")).toBe("application_denied");expect(location.searchParams.get("error_description")).toBe("Application denied user");
  const redirect=await control(ctx,{email});expect(redirect.accounts).toHaveLength(1);expect(redirect.events[0].source.action).toBe("link-account");
  await control(ctx,{clear:true});
  const direct=await ctx.actor().client.linkSocial({provider:"google",idToken:{token:"fixture-id-token"}});expect(direct.error).toBeNull();expect((await control(ctx)).events).toEqual([]);
  return {implicit,before,callback:{status:callback.status,error:location.searchParams.get("error"),message:location.searchParams.get("error_description")},redirect,directStatus:direct.error?.status??200};
 });
}
