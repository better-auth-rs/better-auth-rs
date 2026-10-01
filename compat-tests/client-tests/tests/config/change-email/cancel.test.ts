import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
const profile=process.env.COMPAT_PROFILE!;
async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}){return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body)});}
if(!profile.endsWith("disabled"))for(const mode of ["http","native"]){
 compatScenario(`${mode}: a cancelled update retains storage but change-email still issues credentials and sends the intended email`,async ctx=>{
  const email=`cancel-${mode}@example.test`,newEmail=`cancelled-${mode}@example.test`;
  const signup=await post(ctx,"/api/auth/sign-up/email",{email,name:"Cancelled change",password:"fixture-password"});expect(signup.status).toBe(200);const owner=await signup.json();const headers={cookie:signup.headers.getSetCookie().map(line=>line.split(";",1)[0]).join("; "),"x-user-update-cancel":"true"};
  await post(ctx,"/__test/body-events",{});await post(ctx,"/__test/email-events",{});
  const body={newEmail,callbackURL:"/cancelled",unknown:"raw"};const response=mode==="http"?await post(ctx,"/api/auth/change-email",body,headers):await post(ctx,"/__test/query-native",{path:"/change-email",method:"POST",body,headers});
  expect(response.status).toBe(200);expect(await response.json()).toEqual({status:true});expect(response.headers.getSetCookie().some(line=>line.startsWith("better-auth.session_token="))).toBe(true);
  const events=(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;
  expect(events.map((event:any)=>event.phase)).toEqual(["before","plugin.before","user.update.before",...(profile.endsWith("no-sender")?[]:["email.sender"]),"after"]);
  for(const event of events){expect(event.body).toEqual(["before","plugin.before","after"].includes(event.phase)?body:{newEmail,callbackURL:"/cancelled"});expect(event.requestBody).toBe(mode==="http"?JSON.stringify(body):null);}
  const messages=(await(await fetch(`${ctx.baseURL}/__test/email-events`)).json()).events;
  expect(messages.length).toBe(profile.endsWith("no-sender")?0:1);if(messages.length){expect(messages[0].user.email).toBe(newEmail);expect(messages[0].cookieIssued).toBe(true);}
  const persisted=await post(ctx,"/__test/query-native",{path:"/get-session",headers,query:{disableCookieCache:true}});expect(persisted.status).toBe(200);const user=(await persisted.json()).user;expect(user.id).toBe(owner.user.id);expect(user.email).toBe(email);
  const jar=new Map<string,string>();for(const line of response.headers.getSetCookie()){const pair=line.split(";",1)[0];jar.set(pair.slice(0,pair.indexOf("=")),pair);}const cookie=[...jar.values()].join("; ");const cached=await post(ctx,"/__test/query-native",{path:"/get-session",headers:{cookie}});expect(cached.status).toBe(200);expect((await cached.json()).user.email).toBe(newEmail);
  return {events,messages};
 });
}
