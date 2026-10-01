import {expect} from "bun:test";
import {base32} from "@better-auth/utils/base32";
import {compatScenario} from "../../../support/scenario";

const profile=process.env.COMPAT_PROFILE??"request-two-factor-sqlite";
const passwordless=profile.includes("passwordless");
const nested=profile.includes("nested");
async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}){return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},...(body===undefined?{}:{body:JSON.stringify(body)})});}
async function call(ctx:any,mode:string,path:string,body:any,headers:Record<string,string>={}){return mode==="http"?post(ctx,`/api/auth/two-factor/${path}`,body,headers):post(ctx,"/__test/query-native",{path:`/two-factor/${path}`,method:"POST",...(body===undefined?{}:{body}),headers});}
async function native(ctx:any,path:string,body:any){return post(ctx,"/__test/query-native",{path,method:"POST",...(body===undefined?{}:{body})});}
async function clear(ctx:any){await post(ctx,"/__test/body-events",{});}
async function events(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;}
function jar(){const values=new Map<string,string>();return {take(r:Response){for(const c of r.headers.getSetCookie()){const pair=c.split(";",1)[0],at=pair.indexOf("=");values.set(pair.slice(0,at),pair.slice(at+1));}},headers(){return {cookie:Array.from(values,([key,value])=>`${key}=${value}`).join("; ")};}};}
async function signup(ctx:any,email:string){const r=await post(ctx,"/api/auth/sign-up/email",{name:"Two Factor schema",email,password:"fixture-password"});expect(r.status).toBe(200);return{response:r,data:await r.json()};}

for(const mode of ["http","native"]){
 compatScenario(`${mode}: Two Factor validates all body fields before session middleware and preserves raw hooks`,async ctx=>{
  const cases:[string,any,string][]=[
   ["enable",{password:1,method:null,issuer:[]},'[body.password] Invalid input: expected string, received number; [body.method] Invalid option: expected one of "otp"|"totp"; [body.issuer] Invalid input: expected string, received array'],
   ["disable",{password:null},"[body.password] Invalid input: expected string, received null"],
   ["get-totp-uri",{password:false},"[body.password] Invalid input: expected string, received boolean"],
   ["generate-backup-codes",{password:[]},"[body.password] Invalid input: expected string, received array"],
   ...["verify-totp","verify-otp"].map(path=>[path,{code:null,trustDevice:"false"},"[body.code] Invalid input: expected string, received null; [body.trustDevice] Invalid input: expected boolean, received string"] as [string,any,string]),
   ["verify-backup-code",{code:4,disableSession:"false",trustDevice:null},"[body.code] Invalid input: expected string, received number; [body.disableSession] Invalid input: expected boolean, received string; [body.trustDevice] Invalid input: expected boolean, received null"],
   ["send-otp",{trustDevice:0},"[body.trustDevice] Invalid input: expected boolean, received number"],
   ["send-otp",null,"[body] Invalid input: expected object, received null"],
  ];
  const observed=[];
  for(const [path,body,message]of cases){await clear(ctx);const r=await call(ctx,mode,path,body);const result=await r.json();expect({path,status:r.status,result}).toEqual({path,status:400,result:{code:"VALIDATION_ERROR",message}});const trace=await events(ctx);expect(trace.map((e:any)=>e.phase)).toEqual(["before","plugin.before","after"]);for(const e of trace){expect(e.body).toEqual(body);expect(e.request).toBe(mode==="http");}observed.push({path,result,trace});}
  for(const [path,optional]of [["enable",passwordless],["disable",passwordless],["get-totp-uri",nested],["generate-backup-codes",nested]] as const){await clear(ctx);const r=await call(ctx,mode,path,{unknown:true});expect({path,status:r.status}).toEqual({path,status:optional?401:400});if(!optional)expect(await r.json()).toEqual({code:"VALIDATION_ERROR",message:"[body.password] Invalid input: expected string, received undefined"});}
  const omitted=await call(ctx,mode,"send-otp",undefined);expect(omitted.status).toBe(401);
  return observed;
 });
 compatScenario(`${mode}: Two Factor projected enrollment, OTP delivery, and one-use backup codes retain real authentication`,async ctx=>{
  const account=await signup(ctx,ctx.uniqueEmail(`factor-${mode}`)),cookies=jar();cookies.take(account.response);
  const request=async(path:string,body:any)=>{const r=await call(ctx,mode,path,body,cookies.headers());cookies.take(r);return r;};
  await clear(ctx);
  const raw={password:"fixture-password",issuer:"Schema issuer",unknown:"raw"};
  const enabled=await request("enable",raw);expect(enabled.status).toBe(200);const data=await enabled.json();expect(data.method).toBe("totp");expect(data.backupCodes).toEqual(["first-recovery","second-recovery"]);
  const trace=await events(ctx);expect(trace.some((e:any)=>e.phase==="verify")).toBe(true);for(const e of trace)expect(e.body).toEqual(["before","plugin.before","after"].includes(e.phase)?raw:{password:"fixture-password",method:"totp",issuer:"Schema issuer"});
  const secret=new TextDecoder().decode(base32.decode(new URL(data.totpURI).searchParams.get("secret")!));
  const generated=await native(ctx,"generateTOTP",{secret,unknown:true});expect(generated.status).toBe(200);const {code}=await generated.json();expect(code).toMatch(/^\d{6}$/);
  const invalid=await request("verify-totp",{code:"invalid",trustDevice:false});expect(invalid.status).toBe(401);expect((await invalid.json()).code).toBe("INVALID_CODE");
  const verified=await request("verify-totp",{code,trustDevice:false,unknown:true});expect(verified.status).toBe(200);expect((await verified.json()).user.twoFactorEnabled).toBe(false);
  const persisted=await fetch(`${ctx.baseURL}/api/auth/get-session?disableCookieCache=true`,{headers:cookies.headers()});expect((await persisted.json()).user.twoFactorEnabled).toBe(true);
  const uri=await request("get-totp-uri",{password:"fixture-password",unknown:7});expect(uri.status).toBe(200);expect((await uri.json()).totpURI).toContain("otpauth://totp/");
  const wrong=await request("generate-backup-codes",{password:"wrong"});expect(wrong.status).toBe(400);expect((await wrong.json()).code).toBe("INVALID_PASSWORD");
  const regenerated=await request("generate-backup-codes",{password:"fixture-password",unknown:7});expect(regenerated.status).toBe(200);expect((await regenerated.json()).backupCodes).toEqual(data.backupCodes);
  const read=await native(ctx,"viewBackupCodes",{userId:[account.data.user.id],unknown:true});expect(read.status).toBe(200);expect(await read.json()).toEqual({status:true,backupCodes:data.backupCodes});
  const recovered=await request("verify-backup-code",{code:data.backupCodes[0],disableSession:true,trustDevice:false,unknown:true});expect(recovered.status).toBe(200);expect((await recovered.json()).user.id).toBe(account.data.user.id);
  const duplicate=await request("verify-backup-code",{code:data.backupCodes[0],disableSession:true});expect(duplicate.status).toBe(401);expect((await duplicate.json()).code).toBe("INVALID_BACKUP_CODE");
  const remaining=await native(ctx,"viewBackupCodes",{userId:account.data.user.id});expect(await remaining.json()).toEqual({status:true,backupCodes:["second-recovery"]});
  await clear(ctx);await post(ctx,"/__test/email-events",{});
  const omitted=await request("send-otp",undefined);expect(omitted.status).toBe(200);
  const omittedTrace=await events(ctx);expect(omittedTrace.find((e:any)=>e.phase==="otp.sender").body).toEqual({$undefined:true});
  const firstOtp=(await(await fetch(`${ctx.baseURL}/__test/email-events`)).json()).events.at(-1).otp;
  const firstConfirmed=await request("verify-otp",{code:firstOtp});expect(firstConfirmed.status).toBe(200);
  await clear(ctx);await post(ctx,"/__test/email-events",{});
  const sent=await request("send-otp",{trustDevice:false,unknown:true});expect(sent.status).toBe(200);expect(await sent.json()).toEqual({status:true});
  const sentTrace=await events(ctx);const delivery=sentTrace.find((e:any)=>e.phase==="otp.sender");expect(delivery.body).toEqual({trustDevice:false});
  const otp=(await(await fetch(`${ctx.baseURL}/__test/email-events`)).json()).events.at(-1).otp;
  const confirmed=await request("verify-otp",{code:otp,trustDevice:false,unknown:true});expect(confirmed.status).toBe(200);expect((await confirmed.json()).user.id).toBe(account.data.user.id);
  const disabled=await request("disable",{password:"fixture-password",unknown:true});expect(disabled.status).toBe(200);expect(await disabled.json()).toEqual({status:true});
  const session=await fetch(`${ctx.baseURL}/api/auth/get-session?disableCookieCache=true`,{headers:cookies.headers()});expect((await session.json()).user.twoFactorEnabled).toBe(false);
  return {trace,sentTrace,method:data.method,backupCodes:data.backupCodes,remaining:["second-recovery"],disabled:true};
 });
}

compatScenario("server-only TOTP and backup-code schemas coerce IDs without exposing HTTP routes",async ctx=>{
 const result=[];
 for(const [path,body,message] of [
  ["generateTOTP",undefined,"[body] Invalid input: expected object, received undefined"],
  ["generateTOTP",{secret:7},"[body.secret] Invalid input: expected string, received number"],
  ["viewBackupCodes",{},"[body.userId] Invalid input: expected nonoptional, received undefined"],
 ] as const){const r=await native(ctx,path,body);expect(r.status).toBe(400);const value=await r.json();expect(value).toEqual({code:"VALIDATION_ERROR",message});result.push(value);}
 for(const userId of [null,7,false,[],{},[7]]){const r=await native(ctx,"viewBackupCodes",{userId});expect(r.status).toBe(400);expect((await r.json()).code).toBe("BACKUP_CODES_NOT_ENABLED");}
 for(const path of ["/totp/generate","/two-factor/view-backup-codes"]){const r=await post(ctx,`/api/auth${path}`,{secret:"test",userId:"missing"});expect(r.status).toBe(404);}
 return result;
});
