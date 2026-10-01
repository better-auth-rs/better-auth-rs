import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
type Context=Parameters<Parameters<typeof compatScenario>[1]>[0];
const password="Password123!";
async function control(ctx:Context,json:unknown) {
 const response=await fetch(`${ctx.baseURL}/__test/auth-lifecycle`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(json)});
 expect(response.status,await response.clone().text()).toBe(200);return response.json();
}
async function request(ctx:Context,path:string,json?:unknown,fail?:string,actor="primary") {
 const response=await ctx.actor(actor).fetch(`/api/auth${path}`,{method:json===undefined?"GET":"POST",redirect:"manual",headers:{"content-type":"application/json","x-lifecycle-tag":"request-context",...(fail?{"x-lifecycle-fail":fail}:{})},...(json===undefined?{}:{body:JSON.stringify(json)})});
 return {status:response.status,body:await response.json(),clearsSession:response.headers.getSetCookie().some(cookie=>cookie.startsWith("better-auth.session_token=")&&cookie.includes("Max-Age=0"))};
}
async function signup(ctx:Context,prefix:string,actor="primary") {
 const email=ctx.uniqueEmail(prefix);const result=await request(ctx,"/sign-up/email",{email,password,name:"Lifecycle User",image:"https://example.com/avatar.png"},undefined,actor);
 expect(result.status,JSON.stringify(result.body)).toBe(200);return {email,id:result.body.user.id};
}
export function lifecycleScenarios(mode:"default"|"confirmation"|"zero") {
 compatScenario("password reset awaits completion hooks before revoking sessions and preserves notification failures",async ctx=>{
  const user=await signup(ctx,"reset-lifecycle");
  const sent=await request(ctx,"/request-password-reset",{email:user.email},"reset-send");expect(sent.status).toBe(200);
  const state=await control(ctx,{action:"snapshot",userId:user.id});expect(state.resetLifetime).toBe(mode==="confirmation"?90:3600);
  expect(state.events[0]).toMatchObject({name:"reset-send",email:user.email,department:"ops",hasHidden:true,hasCreatedAt:true,image:"https://example.com/avatar.png",tag:"request-context",path:"/request-password-reset"});
  const failed=await request(ctx,"/reset-password",{token:state.resetToken,newPassword:"ChangedPassword123!"},"reset-complete");expect(failed.status).toBe(400);expect(failed.body.code).toBe("LIFECYCLE_REJECTED");
  const alive=await request(ctx,"/get-session");expect(alive.body.user.id).toBe(user.id);
  const old=await request(ctx,"/sign-in/email",{email:user.email,password},undefined,"old-password");expect(old.status).toBe(401);
  const changed=await request(ctx,"/sign-in/email",{email:user.email,password:"ChangedPassword123!"},undefined,"new-password");expect(changed.status).toBe(200);
  const replay=await request(ctx,"/reset-password",{token:state.resetToken,newPassword:password});expect(replay.status).toBe(400);
  await request(ctx,"/request-password-reset",{email:user.email});const next=await control(ctx,{action:"snapshot"});
  const completed=await request(ctx,"/reset-password",{token:next.resetToken,newPassword:password});expect(completed.status).toBe(200);
  const ended=await request(ctx,"/get-session");expect(ended.body).toBeNull();
  const otherEnded=await request(ctx,"/get-session",undefined,undefined,"new-password");expect(otherEnded.body).toBeNull();
  const events=(await control(ctx,{action:"snapshot"})).events;expect(events.filter((event:any)=>event.name==="reset-complete").every((event:any)=>event.hasHidden&&event.path==="/reset-password")).toBe(true);
  return {sent,failed,alive,old,changed,replay,completed,ended,otherEnded,events,lifetime:state.resetLifetime};
 });
 compatScenario("unlink-account checks freshness before modifying a linked account",async ctx=>{
  const user=await signup(ctx,"unlink-freshness");const linked=await control(ctx,{action:"add-account",userId:user.id});
  await control(ctx,{action:"age",userId:user.id});
  const result=await request(ctx,"/unlink-account",{accountId:linked.accountId});
  expect(result.status).toBe(mode==="zero"?200:403);
  if(mode!=="zero")expect(result.body.code).toBe("SESSION_NOT_FRESH");
  const state=await control(ctx,{action:"snapshot",userId:user.id});expect(state.accounts).toBe(mode==="zero"?1:2);
  return {result,accounts:state.accounts};
 });
 if(mode!=="confirmation") {
  compatScenario("direct deletion uses default freshness, skips it at zero, and permits password proof",async ctx=>{
   const user=await signup(ctx,"delete-stale");await control(ctx,{action:"age",userId:user.id});
   const stale=await request(ctx,"/delete-user",{password:"",token:""});expect(stale.status).toBe(mode==="zero"?200:400);
   if(mode!=="zero")expect(stale.body.code).toBe("SESSION_EXPIRED");
   let proof=null;if(mode!=="zero"){proof=await request(ctx,"/delete-user",{password});expect(proof.status).toBe(200);}
   const state=await control(ctx,{action:"snapshot",userId:user.id});expect(state.userExists).toBe(false);
   expect(state.events.map((event:any)=>event.name)).toEqual(["before-delete","after-delete"]);
   return {stale,proof,events:state.events};
  });
  compatScenario("delete hooks propagate failures and clear credentials after committed deletion",async ctx=>{
   const user=await signup(ctx,"delete-hooks");
   const before=await request(ctx,"/delete-user",{},"before-delete");expect(before.status).toBe(400);expect(before.clearsSession).toBe(false);
   expect((await control(ctx,{action:"snapshot",userId:user.id})).userExists).toBe(true);
   const after=await request(ctx,"/delete-user",{},"after-delete");expect(after.status).toBe(400);expect(after.clearsSession).toBe(true);
   const state=await control(ctx,{action:"snapshot",userId:user.id});expect(state.userExists).toBe(false);
   expect(state.events.every((event:any)=>event.department==="ops"&&!event.hasHidden&&event.hasCreatedAt&&event.tag==="request-context")).toBe(true);
   return {before,after,events:state.events};
  });
 } else {
  compatScenario("delete confirmation keeps the session and consumes the token before owner and hook checks",async ctx=>{
   const owner=await signup(ctx,"delete-confirm");await signup(ctx,"delete-other","other");
   const sent=await request(ctx,"/delete-user",{},"delete-send");expect(sent.status).toBe(200);expect(sent.clearsSession).toBe(false);
   const alive=await request(ctx,"/get-session");expect(alive.body.user.id).toBe(owner.id);
   let state=await control(ctx,{action:"snapshot"});
   const wrongOwner=await request(ctx,`/delete-user/callback?token=${state.deleteToken}`,undefined,undefined,"other");expect(wrongOwner.status).toBe(404);
   const consumed=await request(ctx,`/delete-user/callback?token=${state.deleteToken}`);expect(consumed.status).toBe(404);
   await request(ctx,"/delete-user",{});state=await control(ctx,{action:"clear"});
   const concurrent=await Promise.all([request(ctx,`/delete-user/callback?token=${state.deleteToken}`,undefined,"before-delete"),request(ctx,`/delete-user/callback?token=${state.deleteToken}`,undefined,"before-delete")]);
   const statuses=concurrent.map(result=>result.status).sort();expect(statuses).toEqual([400,404]);
   expect(concurrent.find(result=>result.status===400)!.body.code).toBe("LIFECYCLE_REJECTED");
   const replay=await request(ctx,`/delete-user/callback?token=${state.deleteToken}`);expect(replay.status).toBe(404);
   state=await control(ctx,{action:"snapshot",userId:owner.id});expect(state.userExists).toBe(true);expect(state.events.map((event:any)=>event.name)).toEqual(["before-delete"]);
   await request(ctx,"/delete-user",{});const final=await control(ctx,{action:"snapshot"});
   const after=await request(ctx,`/delete-user/callback?token=${final.deleteToken}`,undefined,"after-delete");expect(after.status).toBe(400);expect(after.clearsSession).toBe(true);
   state=await control(ctx,{action:"snapshot",userId:owner.id});expect(state.userExists).toBe(false);
   return {sent,alive,wrongOwner,consumed,statuses,replay,after,events:state.events};
  });
 }
}
