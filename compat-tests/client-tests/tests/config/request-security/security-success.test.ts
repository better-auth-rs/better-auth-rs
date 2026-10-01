import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
import {authenticator} from "../../phase8/authenticator";
async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}){return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body),redirect:"manual"});}
async function call(ctx:any,mode:string,path:string,body:any,headers:Record<string,string>={}){return mode==="http"?post(ctx,`/api/auth${path}`,body,headers):post(ctx,"/__test/query-native",{method:"POST",path,body,headers:{origin:ctx.baseURL,...headers}});}
async function trace(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;}
function mergeCookie(...responses:Response[]){const jar=new Map<string,string>();for(const response of responses)for(const value of response.headers.getSetCookie()){const pair=value.split(";",1)[0],index=pair.indexOf("=");jar.set(pair.slice(0,index),pair.slice(index+1));}return Array.from(jar,([key,value])=>`${key}=${value}`).join("; ");}
function checkTrace(events:any[],raw:any,projection:any,phase:string,mode:string){expect(events.map(event=>event.phase)).toEqual(["before","plugin.before",phase,"after"]);for(const event of events){expect(event.body).toEqual(event.phase===phase?projection:raw);expect(event.requestBody).toBe(mode==="http"?JSON.stringify(raw):null);}}
for(const mode of ["http","native"]){
 compatScenario(`${mode}: magic sender receives projected input and its real proof creates one verified session`,async ctx=>{
  await post(ctx,"/__test/body-events",{});await post(ctx,"/__test/email-events",{});
  const body={email:`magic-${mode}@request.example`,name:"Magic body",callbackURL:"/complete",metadata:{opaque:{value:true}},unknown:"raw"};
  const response=await call(ctx,mode,"/sign-in/magic-link",body);expect(response.status).toBe(200);expect(await response.json()).toEqual({status:true});
  const events=await trace(ctx);const {unknown,...projection}=body;checkTrace(events,body,projection,"magic.sender",mode);
  const [message]=(await(await fetch(`${ctx.baseURL}/__test/email-events`)).json()).events;expect(message.email).toBe(body.email);expect(message.metadata).toEqual(body.metadata);expect(new URL(message.url).searchParams.get("token")).toBe(message.token);
  const verified=await fetch(message.url,{redirect:"manual"});expect(verified.status).toBe(302);expect(new URL(verified.headers.get("location")!,ctx.baseURL).pathname).toBe("/complete");
  const session=await(await fetch(`${ctx.baseURL}/api/auth/get-session`,{headers:{cookie:mergeCookie(verified)}})).json();expect(session.user.email).toBe(body.email);expect(session.user.name).toBe(body.name);expect(session.user.emailVerified).toBe(true);
  const replay=await fetch(message.url,{redirect:"manual"});expect(replay.status).toBe(302);expect(new URL(replay.headers.get("location")!,ctx.baseURL).searchParams.get("error")).toBe("INVALID_TOKEN");
  return {events,name:session.user.name,emailVerified:session.user.emailVerified,replay:replay.status};
 });
 compatScenario(`${mode}: device normalization reaches the callback and claimed approval redeems once`,async ctx=>{
  const signup=await post(ctx,"/api/auth/sign-up/email",{name:"Device body",email:`device-${mode}@request.example`,password:"fixture-password"});expect(signup.status).toBe(200);const cookie=mergeCookie(signup);
  await post(ctx,"/__test/body-events",{});
  const body={client_id:"body-device",user_id:"",scope:"",unknown:"raw"};const response=await call(ctx,mode,"/device/code",body);expect(response.status).toBe(200);const device=await response.json();const events=await trace(ctx);checkTrace(events,body,{client_id:body.client_id},"device.sender",mode);
  const record=await(await post(ctx,"/__test/device-record",{deviceCode:device.device_code})).json();expect(record.clientId).toBe(body.client_id);const stored={clientId:record.clientId,...(Object.hasOwn(record,"scope")?{scope:record.scope}:{})};expect(stored).toEqual(process.env.COMPAT_PROFILE!.endsWith("-sqlite")?{clientId:body.client_id,scope:null}:{clientId:body.client_id});
  const unclaimed=await call(ctx,mode,"/device/approve",{userCode:device.user_code},{cookie});expect(unclaimed.status).toBe(400);
  const claimed=await fetch(`${ctx.baseURL}/api/auth/device?user_code=${device.user_code}`,{headers:{cookie}});expect(claimed.status).toBe(200);
  const approve=await call(ctx,mode,"/device/approve",{userCode:device.user_code,unknown:"drop"},{cookie});expect(approve.status).toBe(200);expect(await approve.json()).toEqual({success:true});
  const tokenBody={grant_type:"urn:ietf:params:oauth:grant-type:device_code",device_code:device.device_code,client_id:body.client_id,unknown:"drop"};
  const token=await call(ctx,mode,"/device/token",tokenBody);expect(token.status).toBe(200);const credentials=await token.json();expect(credentials.token_type).toBe("Bearer");expect(credentials.access_token.length).toBeGreaterThan(0);
  const replay=await call(ctx,mode,"/device/token",tokenBody);expect(replay.status).toBe(400);const rejected=await replay.json();expect(rejected.error).toBe("invalid_grant");
  const empty=await call(ctx,mode,"/device/code",{client_id:""});expect(empty.status).toBe(400);expect(await empty.json()).toEqual({error:"invalid_request",error_description:"client_id is required"});
  return {events,stored,unclaimed:await unclaimed.json(),claimed:await claimed.json(),rejected};
 });
}
compatScenario("real WebAuthn registration and updates trim names after raw hooks without altering proof bytes",async ctx=>{
 const signup=await post(ctx,"/api/auth/sign-up/email",{name:"Passkey body",email:"passkey@request.example",password:"fixture-password"});expect(signup.status).toBe(200);
 const options=await fetch(`${ctx.baseURL}/api/auth/passkey/generate-register-options`,{headers:{cookie:mergeCookie(signup),origin:ctx.baseURL}});expect(options.status).toBe(200);const optionsBody=await options.json();
 const key=authenticator("request-security-credential");const registration={response:key.register(optionsBody,ctx.baseURL,true),name:"  \uFEFF Trimmed key \uFEFF ",createSession:false,unknown:"raw"};
 await post(ctx,"/__test/body-events",{});
 const registered=await post(ctx,"/api/auth/passkey/verify-registration",registration,{cookie:mergeCookie(signup,options)});expect(registered.status).toBe(200);const passkey=await registered.json();expect(passkey.name).toBe("Trimmed key");
 const before=await trace(ctx);expect(before.map((event:any)=>event.phase)).toEqual(["before","plugin.before","after"]);for(const event of before){expect(event.body).toEqual(registration);expect(event.requestBody).toBe(JSON.stringify(registration));}
 const update={id:passkey.id,name:"  \uFEFF Renamed key \uFEFF ",unknown:"raw"};const updated=await call(ctx,"native","/passkey/update-passkey",update,{cookie:mergeCookie(signup)});expect(updated.status).toBe(200);
 const listed=await(await fetch(`${ctx.baseURL}/api/auth/passkey/list-user-passkeys`,{headers:{cookie:mergeCookie(signup)}})).json();expect(listed).toHaveLength(1);expect(listed[0].name).toBe("Renamed key");
 const deleted=await call(ctx,"native","/passkey/delete-passkey",{id:passkey.id,unknown:"raw"},{cookie:mergeCookie(signup)});expect(deleted.status).toBe(200);const after=await(await fetch(`${ctx.baseURL}/api/auth/passkey/list-user-passkeys`,{headers:{cookie:mergeCookie(signup)}})).json();expect(after).toEqual([]);
 return {name:passkey.name,updated:await updated.json(),deleted:await deleted.json(),after};
});
compatScenario("device form multiplicity is checked from original Request after schema projection",async ctx=>{
 const observed=[];
 for(const [body,status,message] of [["client_id=&client_id=form-device&scope=&unknown=raw",200,null],["client_id=a&client_id=b",400,"client_id must not be repeated"],["client_id=form-device&scope=a&scope=b",400,"scope must not be repeated"]] as const){
  await post(ctx,"/__test/body-events",{});
  const response=await fetch(`${ctx.baseURL}/api/auth/device/code`,{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded",origin:ctx.baseURL},body});expect(response.status).toBe(status);const result=await response.json();if(message)expect(result).toEqual({error:"invalid_request",error_description:message});
  const events=await trace(ctx);for(const event of events)expect(event.requestBody).toBe(body);if(status===200)expect(events.find((event:any)=>event.phase==="device.sender").body).toEqual({client_id:"form-device"});observed.push({status,events,...(message?{result}:{})});
 }
 return observed;
});
