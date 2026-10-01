import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
import contracts from "./invalid-fields.json";

async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}){return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},...(body===undefined?{}:{body:JSON.stringify(body)})});}
async function call(ctx:any,mode:string,path:string,body:any,headers:Record<string,string>={}){return mode==="http"?post(ctx,`/api/auth${path}`,body,headers):post(ctx,"/__test/query-native",{path,method:"POST",...(body===undefined?{}:{body}),headers});}
async function clear(ctx:any){await post(ctx,"/__test/body-events",{});}
async function events(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;}
async function messages(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/email-events`)).json()).events;}
function jar(){const values=new Map<string,string>();return {take(r:Response){for(const c of r.headers.getSetCookie()){const pair=c.split(";",1)[0],at=pair.indexOf("=");values.set(pair.slice(0,at),pair.slice(at+1));}},headers(){return {cookie:Array.from(values,([key,value])=>`${key}=${value}`).join("; ")};}};}
async function projection(ctx:any,mode:string,raw:any,projected:any,required:string[],after=raw){
 const trace=await events(ctx);
 for(const phase of required)expect(trace.some((event:any)=>event.phase===phase)).toBe(true);
 for(const event of trace){
  const expected=event.phase==="after"?after:["before","plugin.before"].includes(event.phase)?raw:projected;
  expect({phase:event.phase,body:event.body}).toEqual({phase:event.phase,body:expected});
  expect(event.request).toBe(mode==="http");
  if(mode==="http")expect(JSON.parse(event.requestBody)).toEqual(raw);
 }
 return trace;
}
const wrongFields={email:7,type:"invalid",otp:[],name:false,image:null,newEmail:8,phoneNumber:false,password:9,code:null,rememberMe:7,disableSession:null,updatePhoneNumber:"true",newPassword:0};

for(const mode of ["http","native"]){
 compatScenario(`${mode}: OTP and Phone schemas reject invalid input before authentication`,async ctx=>{
  const observed=[];
  for(const {path,message}of contracts){await clear(ctx);const r=await call(ctx,mode,path,wrongFields);const result=await r.json();expect({path,status:r.status,result}).toEqual({path,status:400,result:{code:"VALIDATION_ERROR",message}});const trace=await projection(ctx,mode,wrongFields,{},["before","plugin.before","after"]);expect(trace.length).toBe(3);observed.push({path,result,trace});}
  for(const path of ["/email-otp/send-verification-otp","/sign-in/email-otp","/phone-number/verify"]){for(const [body,type]of [[undefined,"undefined"],[null,"null"],[[],"array"],[7,"number"]]){const r=await call(ctx,mode,path,body);const record=path!=="/email-otp/send-verification-otp";expect(await r.json()).toEqual({code:"VALIDATION_ERROR",message:`[body] Invalid input: expected object, received ${type}${record?`; [body] Invalid input: expected record, received ${type}`:""}`});}}
  await clear(ctx);const raw={email:7,type:"wrong",unknown:"raw"};const patched=await call(ctx,mode,"/email-otp/send-verification-otp",raw,{"x-otp-patch":"true"});expect(patched.status).toBe(200);const trace=await projection(ctx,mode,raw,{email:"patched@test.com",type:"sign-in"},["email.otp.sender"],{...raw,email:"patched@test.com",type:"sign-in"});
  return {observed,trace};
 });
 compatScenario(`${mode}: Email OTP retains record fields, consumes codes, resets passwords and changes email`,async ctx=>{
  const email=ctx.uniqueEmail(`otp-${mode}`),cookies=jar();
  const request=async(path:string,body:any)=>{const r=await call(ctx,mode,path,body,cookies.headers());cookies.take(r);return r;};
  await clear(ctx);const send={email,type:"sign-in",unknown:"raw"};expect((await request("/email-otp/send-verification-otp",send)).status).toBe(200);const sent=await projection(ctx,mode,send,{email,type:"sign-in"},["email.otp.sender"]);
  await clear(ctx);const signin=JSON.parse(JSON.stringify({email,otp:"123456",name:"OTP schema",image:"https://example.test/image.png",unknown:{retained:true}}).replace(/}$/,',"__proto__":{"safe":true}}'));
  const signed=await request("/sign-in/email-otp",signin);expect(signed.status).toBe(200);const user=(await signed.json()).user;expect(user.email).toBe(email);expect(user.emailVerified).toBe(true);expect(user.name).toBe("OTP schema");
  const projected={...signin};delete projected.__proto__;const created=await projection(ctx,mode,signin,projected,["user.before","user.after","session.before","session.after"]);
  const replay=await request("/sign-in/email-otp",signin);expect(replay.status).toBe(400);
  for(const path of ["/email-otp/request-password-reset","/forget-password/email-otp"]){await clear(ctx);expect((await request(path,{email,unknown:true})).status).toBe(200);await projection(ctx,mode,{email,unknown:true},{email},["email.otp.sender"]);}
  const reset=await request("/email-otp/reset-password",{email,otp:"123456",password:"fixture-password",unknown:true});expect(reset.status).toBe(200);
  const password=await call(ctx,mode,"/sign-in/email",{email,password:"fixture-password"});expect(password.status).toBe(200);
  const nextEmail=ctx.uniqueEmail(`changed-${mode}`);await clear(ctx);const change={newEmail:nextEmail,unknown:1};expect((await request("/email-otp/request-email-change",change)).status).toBe(200);const changing=await projection(ctx,mode,change,{newEmail:nextEmail},["email.otp.sender"]);
  expect((await request("/email-otp/change-email",{newEmail:nextEmail,otp:"123456",unknown:true})).status).toBe(200);
  const persisted=await fetch(`${ctx.baseURL}/api/auth/get-session?disableCookieCache=true`,{headers:cookies.headers()});expect((await persisted.json()).user.email).toBe(nextEmail);
  return {sent,created,changing,email,nextEmail,replay:await replay.json()};
 });
 compatScenario(`${mode}: Email verification checks preserve codes until verification consumes them`,async ctx=>{
  const email=ctx.uniqueEmail(`verify-${mode}`);const account=await post(ctx,"/api/auth/sign-up/email",{email,name:"Verify OTP",password:"fixture-password"});expect(account.status).toBe(200);const cookies=jar();cookies.take(account);
  expect((await call(ctx,mode,"/email-otp/send-verification-otp",{email,type:"email-verification",unknown:true})).status).toBe(200);
  const checked=await call(ctx,mode,"/email-otp/check-verification-otp",{email,type:"email-verification",otp:"123456",unknown:true});expect(checked.status).toBe(200);
  await clear(ctx);const raw={email,otp:"123456",unknown:true};const verified=await call(ctx,mode,"/email-otp/verify-email",raw);expect(verified.status).toBe(200);const trace=await projection(ctx,mode,raw,{email,otp:"123456"},["user.update.before","user.update.after"]);
  const persisted=await fetch(`${ctx.baseURL}/api/auth/get-session?disableCookieCache=true`,{headers:cookies.headers()});expect((await persisted.json()).user.emailVerified).toBe(true);
  const replay=await call(ctx,mode,"/email-otp/verify-email",raw);expect(replay.status).toBe(400);return {trace,replay:await replay.json()};
 });
 compatScenario(`${mode}: Phone projection preserves signup fields and stored OTP consumption`,async ctx=>{
  const phone=mode==="http"?"+15555550123":"+15555550124";
  await clear(ctx);const send={phoneNumber:phone,unknown:true};const sent=await call(ctx,mode,"/phone-number/send-otp",send);expect(sent.status).toBe(200);const sentTrace=await projection(ctx,mode,send,{phoneNumber:phone},["phone.otp.sender"]);
  const code=(await messages(ctx)).filter((x:any)=>x.kind==="phone-otp"&&x.phoneNumber===phone).at(-1).code;expect(code).toMatch(/^\d{6}$/);
  const raw=JSON.parse(JSON.stringify({phoneNumber:phone,code,disableSession:true,updatePhoneNumber:false,unknown:{retained:true}}).replace(/}$/,',"__proto__":{"safe":true}}'));
  await clear(ctx);const verified=await call(ctx,mode,"/phone-number/verify",raw);expect(verified.status).toBe(200);const result=await verified.json();expect(result.token).toBeNull();expect(result.user.phoneNumberVerified).toBe(true);expect(result.user.phoneNumber).toBe(phone);
  const projected={...raw};delete projected.__proto__;const trace=await projection(ctx,mode,raw,projected,["user.before","user.after"]);
  const replay=await call(ctx,mode,"/phone-number/verify",raw);expect(replay.status).toBe(400);
  await clear(ctx);const resetSend=await call(ctx,mode,"/phone-number/request-password-reset",send);expect(resetSend.status).toBe(200);await projection(ctx,mode,send,{phoneNumber:phone},["phone.reset.sender"]);
  const otp=(await messages(ctx)).filter((x:any)=>x.kind==="phone-reset"&&x.phoneNumber===phone).at(-1).code;
  const reset=await call(ctx,mode,"/phone-number/reset-password",{otp,phoneNumber:phone,newPassword:"fixture-password",unknown:true});expect(reset.status).toBe(200);
  await clear(ctx);const signin={phoneNumber:phone,password:"fixture-password",rememberMe:false,unknown:true};const signed=await call(ctx,mode,"/sign-in/phone-number",signin);expect(signed.status).toBe(200);expect((await signed.json()).user.id).toBe(result.user.id);const signTrace=await projection(ctx,mode,signin,{phoneNumber:phone,password:"fixture-password",rememberMe:false},["verify","session.before","session.after"]);
  const normalizedTrace=trace.map((event:any)=>({...event,body:{...event.body,code:"<otp>"},requestBody:event.requestBody?JSON.stringify({...JSON.parse(event.requestBody),code:"<otp>"}):null}));
  return {sentTrace,trace:normalizedTrace,signTrace,replay:await replay.json()};
 });
}
