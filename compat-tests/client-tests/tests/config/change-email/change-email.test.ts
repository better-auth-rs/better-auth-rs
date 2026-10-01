import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
const profile=process.env.COMPAT_PROFILE!;
const disabled=profile.endsWith("disabled"),noSender=profile.endsWith("no-sender"),noConfirmation=profile.endsWith("no-confirmation");
async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}){return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body)});}
async function signup(ctx:any,suffix:string){const response=await post(ctx,"/api/auth/sign-up/email",{email:`change-${suffix}@example.test`,name:"Complete sender snapshot",image:"https://example.test/avatar.png",password:"fixture-password"});expect(response.status).toBe(200);return {...await response.json(),headers:{cookie:response.headers.getSetCookie().map(line=>line.split(";",1)[0]).join("; ")}};}
async function change(ctx:any,mode:string,body:any,headers:Record<string,string>={}){return mode==="http"?post(ctx,"/api/auth/change-email",body,headers):post(ctx,"/__test/query-native",{path:"/change-email",method:"POST",body,headers});}
async function clear(ctx:any){await post(ctx,"/__test/body-events",{});await post(ctx,"/__test/email-events",{});}
async function read(ctx:any,path:string){return(await(await fetch(`${ctx.baseURL}${path}`)).json()).events;}
async function actualUser(ctx:any,headers:any){const response=await post(ctx,"/__test/query-native",{path:"/get-session",headers,query:{disableCookieCache:true}});expect(response.status).toBe(200);return(await response.json()).user;}
async function assertTrace(ctx:any,body:any,mode:string,phases:string[]){const events=await read(ctx,"/__test/body-events");expect(events.map((event:any)=>event.phase)).toEqual(["before","plugin.before",...phases,"after"]);for(const event of events){expect(event.body).toEqual(["before","plugin.before","after"].includes(event.phase)?body:{newEmail:body.newEmail,callbackURL:body.callbackURL});expect(event.requestBody).toBe(mode==="http"?JSON.stringify(body):null);}return events;}
for(const mode of ["http","native"]){
 compatScenario(`${mode}: change-email preserves authorization and configuration error order`,async ctx=>{
  await clear(ctx);const invalid=await change(ctx,mode,{newEmail:"invalid"});expect(invalid.status).toBe(400);expect(await invalid.json()).toEqual({code:"VALIDATION_ERROR",message:"[body.newEmail] Invalid email address"});
  const unauthorized=await change(ctx,mode,{newEmail:"valid@example.test"});expect(unauthorized.status).toBe(401);expect(await unauthorized.json()).toEqual({code:"UNAUTHORIZED",message:"Unauthorized"});
  const owner=await signup(ctx,`${mode}-config-owner`),target=await signup(ctx,`${mode}-config-target`);
  await post(ctx,"/__test/query-user-verified",{id:owner.user.id,emailVerified:true});
  const results=[];
  for(const email of [target.user.email,`unregistered-${mode}@example.test`]){
   await clear(ctx);const body={newEmail:email,callbackURL:"",unknown:"raw"};const response=await change(ctx,mode,body,owner.headers);const value=await response.json();
   if(disabled||noSender){expect(response.status).toBe(400);expect(value).toEqual(disabled?{code:"CHANGE_EMAIL_DISABLED",message:"Change email is disabled"}:{message:"Verification email isn't enabled"});expect(await read(ctx,"/__test/email-events")).toEqual([]);await assertTrace(ctx,body,mode,[]);}
   else {expect(response.status).toBe(200);expect(value).toEqual({status:true});expect((await read(ctx,"/__test/email-events")).length).toBe(email===target.user.email?0:1);}
   expect(response.headers.getSetCookie().some(line=>line.startsWith("better-auth.session_token="))).toBe(false);
   expect((await actualUser(ctx,owner.headers)).email).toBe(owner.user.email);
   results.push({status:response.status,value,events:await read(ctx,"/__test/email-events")});
  }
  return results;
 });
 compatScenario(`${mode}: change-email persists before delivery and reads verified state beyond stale cookies`,async ctx=>{
  const owner=await signup(ctx,`${mode}-flow-owner`),target=await signup(ctx,`${mode}-flow-target`);
  const results=[];
  await clear(ctx);const existingBody={newEmail:target.user.email,callbackURL:"",unknown:"raw"};const existing=await change(ctx,mode,existingBody,owner.headers);
  if(disabled){expect(existing.status).toBe(400);expect(await existing.json()).toEqual({code:"CHANGE_EMAIL_DISABLED",message:"Change email is disabled"});return {disabled:true};}
  expect(existing.status).toBe(200);expect(await existing.json()).toEqual({status:true});expect(await read(ctx,"/__test/email-events")).toEqual([]);await assertTrace(ctx,existingBody,mode,[]);expect(existing.headers.getSetCookie().some(line=>line.startsWith("better-auth.session_token="))).toBe(false);expect((await actualUser(ctx,owner.headers)).email).toBe(owner.user.email);
  const newEmail=`changed-${mode}@example.test`,body={newEmail:newEmail.toUpperCase(),callbackURL:"",unknown:"raw"};
  await clear(ctx);const changed=await change(ctx,mode,body,{...owner.headers,"x-email-fail":"true"});expect(changed.status).toBe(200);expect(await changed.json()).toEqual({status:true});expect(changed.headers.getSetCookie().some(line=>line.startsWith("better-auth.session_token="))).toBe(true);
  const updated=await actualUser(ctx,owner.headers);expect(updated.email).toBe(newEmail);expect(updated.emailVerified).toBe(false);
  const trace=await assertTrace(ctx,body,mode,["user.update.before","user.update.after",...(noSender?[]:["email.sender"])]);
  const emails=await read(ctx,"/__test/email-events");expect(emails.length).toBe(noSender?0:1);
  if(!noSender){const email=emails[0];expect(email.kind).toBe("verification");expect(email.user).toMatchObject({id:owner.user.id,name:owner.user.name,image:owner.user.image,email:newEmail,emailVerified:false});expect(email.claims).toEqual({email:newEmail,updateTo:null,requestType:null,expiresIn:noConfirmation?90:3600});expect(email.callback).toBe("/");expect(email.cookieIssued).toBe(true);expect(email.request).toBe(mode==="http");}
  results.push({trace,emails});
  await post(ctx,"/__test/query-user-verified",{id:owner.user.id,emailVerified:true});
  await clear(ctx);const pendingEmail=`pending-${mode}@example.test`,pendingBody={newEmail:pendingEmail,callbackURL:"/verified",unknown:"raw"};const pending=await change(ctx,mode,pendingBody,{...owner.headers,"x-email-fail":"true"});
  if(noSender){expect(pending.status).toBe(400);expect(await pending.json()).toEqual({message:"Verification email isn't enabled"});await assertTrace(ctx,pendingBody,mode,[]);}
  else{expect(pending.status).toBe(200);expect(await pending.json()).toEqual({status:true});const phase=noConfirmation?"email.sender":"email.confirmation";await assertTrace(ctx,pendingBody,mode,[phase]);const sent=await read(ctx,"/__test/email-events");expect(sent.length).toBe(1);expect(sent[0].kind).toBe(noConfirmation?"verification":"confirmation");expect(sent[0].user).toMatchObject({id:owner.user.id,name:owner.user.name,image:owner.user.image,email:noConfirmation?pendingEmail:newEmail,emailVerified:true});expect(sent[0].newEmail).toBe(noConfirmation?null:pendingEmail);expect(sent[0].claims).toEqual({email:newEmail,updateTo:pendingEmail,requestType:noConfirmation?"change-email-verification":"change-email-confirmation",expiresIn:noConfirmation?90:3600});expect(sent[0].cookieIssued).toBe(false);expect(sent[0].request).toBe(mode==="http");results.push({emails:sent});}
  expect((await actualUser(ctx,owner.headers)).email).toBe(newEmail);expect(pending.headers.getSetCookie().some(line=>line.startsWith("better-auth.session_token="))).toBe(false);
  return results;
 });
}
