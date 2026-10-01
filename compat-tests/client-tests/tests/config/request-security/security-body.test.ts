import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";

async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}){return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body)});}
async function call(ctx:any,mode:string,path:string,body:any){return mode==="http"?post(ctx,`/api/auth${path}`,body):post(ctx,"/__test/query-native",{method:"POST",path,...(body===undefined?{}:{body}),headers:{}});}
async function trace(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;}
for(const mode of ["http","native"]){
 compatScenario(`${mode}: security plugin schemas aggregate errors before authentication and retain raw hook input`,async ctx=>{
  const cases:[string,any,string][]=[
   ["/sign-in/magic-link",{email:"invalid",name:7,callbackURL:false,newUserCallbackURL:false,errorCallbackURL:null,metadata:[]},'[body.email] Invalid email address; [body.name] Invalid input: expected string, received number; [body.callbackURL] Invalid input: expected string, received boolean; [body.newUserCallbackURL] Invalid input: expected string, received boolean; [body.errorCallbackURL] Invalid input: expected string, received null; [body.metadata] Invalid input: expected record, received array'],
   ["/one-tap/callback",{idToken:null,callbackURL:false},'[body.idToken] Invalid input: expected string, received null; [body.callbackURL] Invalid input: expected string, received boolean'],
   ["/passkey/verify-registration",{name:7,createSession:"true"},'[body.response] Invalid input: expected nonoptional, received undefined; [body.name] Invalid input: expected string, received number; [body.createSession] Invalid input: expected boolean, received string'],
   ["/passkey/verify-authentication",{response:[]},'[body.response] Invalid input: expected record, received array'],
   ["/passkey/update-passkey",{id:7,name:" \uFEFF "},'[body.id] Invalid input: expected string, received number; [body.name] Too small: expected string to have >=1 characters'],
   ["/passkey/delete-passkey",{id:null},'[body.id] Invalid input: expected string, received null'],
   ["/device/code",{client_id:7,user_id:false,scope:[]},'[body.client_id] Invalid input: expected string, received number; [body.user_id] Invalid input: expected string, received boolean; [body.scope] Invalid input: expected string, received array'],
   ["/device/token",{grant_type:"wrong",device_code:null,client_id:7},'[body.grant_type] Invalid input: expected "urn:ietf:params:oauth:grant-type:device_code"; [body.device_code] Invalid input: expected string, received null; [body.client_id] Invalid input: expected string, received number'],
   ...["/device/approve","/device/deny"].map(path=>[path,{userCode:7},'[body.userCode] Invalid input: expected string, received number'] as [string,any,string]),
   ...["/siwe/nonce","/siwe/get-nonce"].map(path=>[path,{unknown:1},'[body] Unrecognized key: "unknown"'] as [string,any,string]),
   ["/siwe/verify",{message:7,signature:""},'[body.message] Invalid input: expected string, received number; [body.signature] Too small: expected string to have >=1 characters'],
   ["/siwe/verify",{message:"",signature:""},'[body.message] Too small: expected string to have >=1 characters; [body.signature] Too small: expected string to have >=1 characters; [body.email] Email is required when the anonymous plugin option is disabled.'],
   ["/siwe/verify",{message:"x",signature:"x",email:"",unknown:1},'[body.email] Invalid email address; [body] Unrecognized key: "unknown"; [body.email] Email is required when the anonymous plugin option is disabled.'],
  ];
  const observed=[];
  for(const [path,body,message] of cases){
   await post(ctx,"/__test/body-events",{});
   const response=await call(ctx,mode,path,body);const result=await response.json();
   expect({path,status:response.status,result}).toEqual({path,status:400,result:path==="/device/code"?{error:"invalid_request",error_description:message}:{code:"VALIDATION_ERROR",message}});
   const events=await trace(ctx);expect(events.map((event:any)=>event.phase)).toEqual(["before","plugin.before","after"]);
   for(const event of events){expect(event.body).toEqual(body);expect(event.request).toBe(mode==="http");expect(event.requestBody).toBe(mode==="http"?JSON.stringify(body):null);}
   observed.push({path,result,events});
  }
  return observed;
 });
 compatScenario(`${mode}: nonce body omission and SIWE native Request requirement remain distinct`,async ctx=>{
  const observed=[];
  for(const body of [undefined,{},null]){
   await post(ctx,"/__test/body-events",{});
   const response=await call(ctx,mode,"/siwe/nonce",body);const result=await response.json();
   expect(response.status).toBe(body===null?400:200);const events=await trace(ctx);
   expect(events.map((event:any)=>event.phase)).toEqual(body===null?["before","plugin.before","after"]:["before","plugin.before","siwe.nonce","after"]);
   for(const event of events)expect(event.body).toEqual(body===undefined?{$undefined:true}:body);
   observed.push({result,events});
  }
  const body={message:"not-a-siwe-message",signature:"signature",email:"wallet@example.com"};
  const response=await call(ctx,mode,"/siwe/verify",body);const result=await response.json();
  expect(response.status).toBe(mode==="http"?401:400);
  if(mode==="native")expect(result).toEqual({code:"VALIDATION_ERROR",message:"Request is required"});
  const original=await post(ctx,"/__test/query-native",{method:"POST",path:"/siwe/verify",body,request:`${ctx.baseURL}/api/auth/siwe/verify`});
  expect(original.status).toBe(401);expect(await original.json()).toEqual(mode==="http"?result:{message:"Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID",status:401,code:"UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"});
  return {observed,result};
 });
}

compatScenario("HTTP origin validation rejects truthy callback types before endpoint body validation",async ctx=>{
 const observed=[];
 for(const [path,body,message] of [["/sign-in/magic-link",{email:7,newUserCallbackURL:[]},"Invalid newUserCallbackURL: expected a string"],["/one-tap/callback",{idToken:null,callbackURL:7},"Invalid callbackURL: expected a string"]] as const){
  await post(ctx,"/__test/body-events",{});const response=await call(ctx,"http",path,body);const result=await response.json();expect(response.status).toBe(400);expect(result).toEqual({message});const events=await trace(ctx);expect(events).toEqual([]);observed.push({result,events});
 }
 return observed;
});
