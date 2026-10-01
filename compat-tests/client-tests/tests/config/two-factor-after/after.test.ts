import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
async function call(ctx:any,input:any){const response=await fetch(`${ctx.baseURL}/__test/two-factor-after`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(input)});expect(response.status).toBe(200);const value=await response.json();expect(value.fixtureError).toBeUndefined();return value;}
const phases=(value:any)=>value.events.map((event:any)=>event.phase);
const completed=["session-created","user-after","plugin-before-2fa","session-delete-before","session-delete-after","proof-create","proof-create","plugin-after-2fa"];
compatScenario("two factor runs after user hooks for each credential endpoint and native call",async ctx=>{
 const values=[];
 for(const native of [false,true])for(const kind of ["email","username","phone"]){
  const value=await call(ctx,{native,kind});expect(value.status).toBe(200);expect(value.body).toEqual({twoFactorRedirect:true,twoFactorMethods:["otp"]});expect(value.sessions).toBe(0);expect(value.proofs).toBe(2);expect(phases(value)).toEqual(completed);
  expect(value.events[1]).toMatchObject({newSession:true,sessions:1,proofs:0,returned:{token:true,user:{email:"factor@example.test",twoFactorEnabled:true}}});
  expect(value.events.at(-1)).toMatchObject({newSession:false,sessions:0,proofs:2,returned:value.body});
  expect(value.cookies.filter((cookie:any)=>cookie.name==="better-auth.session_token")).toEqual([{name:"better-auth.session_token",empty:true,clear:true}]);values.push(value);
 }
 return values;
});
compatScenario("two factor uses the issued snapshot after user response replacement or API error",async ctx=>{
 const values=[];for(const native of [false,true])for(const mode of ["replace","api-error","clear"]){
  const value=await call(ctx,{native,mode});expect(value.status).toBe(200);
  if(mode==="clear"){expect(value.body.token).toBe(true);expect(value.sessions).toBe(1);expect(value.proofs).toBe(0);expect(phases(value)).toEqual(["session-created","user-after","plugin-before-2fa","plugin-after-2fa"]);expect(value.events[2].newSession).toBe(false);}
  else {expect(value.body.twoFactorRedirect).toBe(true);expect(phases(value)).toEqual(completed);expect(value.sessions).toBe(0);expect(value.events[2].returned).toEqual(mode==="replace"?{custom:true}:{apiError:{status:400,body:{code:"USER_AFTER_ERROR",message:"user after rejected"}}});}
  values.push(value);
 }return values;
});
compatScenario("two factor stops on ordinary after, session deletion, or proof creation failures",async ctx=>{
 const values=[];for(const native of [false,true])for(const mode of ["ordinary-error","delete-error","proof-error"]){
  const value=await call(ctx,{native,mode});
  if(native)expect(value.error).toEqual({ordinary:true,message:mode==="ordinary-error"?"user after failed":mode==="delete-error"?"session deletion rejected":"challenge creation rejected",code:null});
  else {expect(value.status).toBe(500);expect(value.body).toBeNull();}
  expect(value.proofs).toBe(0);expect(value.sessions).toBe(mode==="proof-error"?0:1);
  expect(phases(value)).toEqual(mode==="ordinary-error"?["session-created","user-after"]:mode==="delete-error"?completed.slice(0,4):completed.slice(0,6));values.push(value);
 }return values;
});
compatScenario("two factor clears pending credential chunks and retains both remember markers",async ctx=>{
 const values=[];for(const native of [false,true]){const value=await call(ctx,{native,mode:"cookies"});expect(value.body.twoFactorRedirect).toBe(true);expect(value.cookies.some((cookie:any)=>cookie.name==="better-auth.session_data.0")).toBe(false);expect(value.cookies.filter((cookie:any)=>cookie.name==="better-auth.dont_remember")).toEqual(Array(2).fill({name:"better-auth.dont_remember",empty:false,clear:false}));values.push(value);}return values;
});
compatScenario("a real trusted device retains the issued session and rotates its proof",async ctx=>{
 const invalid=await call(ctx,{cookie:"better-auth.trust_device=invalid-signature"});expect(invalid.body.twoFactorRedirect).toBe(true);expect(invalid.cookies.some((cookie:any)=>cookie.name==="better-auth.trust_device")).toBe(false);
 const post=async(path:string,body:any,cookie="")=>fetch(`${ctx.baseURL}/api/auth${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...(cookie?{cookie}:{})},body:JSON.stringify(body)});
 const cookie=(response:Response,name:string)=>response.headers.getSetCookie().find(line=>line.startsWith(name+"="))!.split(";")[0];
 const signed=await post("/sign-in/email",{email:"factor@example.test",password:"password123",rememberMe:false});expect(signed.status).toBe(200);
 const pending=cookie(signed,"better-auth.two_factor");
 const sent=await post("/two-factor/send-otp",{},pending);expect(sent.status).toBe(200);
 const state=await call(ctx,{action:"state"});expect(state.otp.length).toBe(6);
 const verified=await post("/two-factor/verify-otp",{code:state.otp,trustDevice:true},pending);expect(verified.status).toBe(200);
 const trusted=cookie(verified,"better-auth.trust_device");
 const value=await call(ctx,{clear:false,cookie:trusted});expect(value.status).toBe(200);expect(value.body.twoFactorRedirect).toBeUndefined();expect(value.body.token).toBe(true);expect(phases(value)).toEqual(["session-created","user-after","plugin-before-2fa","plugin-after-2fa"]);expect(value.events.at(-1).newSession).toBe(true);expect(value.cookies.some((cookie:any)=>cookie.name==="better-auth.trust_device"&&!cookie.empty)).toBe(true);
 return value;
});
