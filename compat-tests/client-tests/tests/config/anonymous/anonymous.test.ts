import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("anonymous identities cannot repeat and upgrade through real sign-in", async (ctx) => {
  const anonymous = await ctx.rawRequest({ path: "/api/auth/sign-in/anonymous", method: "POST", json: {} });
  expect(anonymous.status).toBe(200);
  expect(anonymous.body.user).toMatchObject({ name: "Anonymous", emailVerified: false, isAnonymous: true });
  const repeated = await ctx.rawRequest({ path: "/api/auth/sign-in/anonymous", method: "POST", json: {} });
  expect(repeated.status).toBe(400);
  expect(repeated.body.code).toBe("ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY");
  const signup = await ctx.actor().client.signUp.email({ email: ctx.uniqueEmail("upgraded"), name: "Upgraded", password: "Password123!" });
  expect(signup.error).toBeNull();
  expect(signup.data.user.isAnonymous).toBe(false);
  const response = await fetch(`${ctx.baseURL}/__test/identity`, {method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({action:"links"})});
  const links = await response.json();
  expect(links).toHaveLength(1);
  expect(links[0]).toEqual({anonymousId:anonymous.body.user.id,newId:signup.data.user.id});
  const persisted = await ctx.actor().client.getSession();
  expect(persisted.data.user.id).toBe(signup.data.user.id);
  const forbidden = await ctx.rawRequest({ path: "/api/auth/delete-anonymous-user", method: "POST", json: {} });
  expect(forbidden.status).toBe(403);
  expect(forbidden.body.code).toBe("USER_IS_NOT_ANONYMOUS");
  return ctx.snapshot({anonymous,repeated,signup,persisted,forbidden,linked:links.length});
});

compatScenario("anonymous deletion revokes the session", async (ctx) => {
  const anonymous = await ctx.rawRequest({ path: "/api/auth/sign-in/anonymous", method: "POST", json: {} });
  expect(anonymous.status).toBe(200);
  const deleted = await ctx.rawRequest({ path: "/api/auth/delete-anonymous-user", method: "POST", json: {} });
  expect(deleted.status).toBe(200);
  expect(deleted.body).toEqual({success:true});
  const session = await ctx.actor().client.getSession();
  expect(session.data).toBeNull();
  const repeated = await ctx.rawRequest({ path: "/api/auth/delete-anonymous-user", method: "POST", json: {} });
  expect(repeated.status).toBe(401);
  expect(repeated.body).toEqual({code:"UNAUTHORIZED",message:"Unauthorized"});
  return ctx.snapshot({deleted,session,repeated});
});

compatScenario("anonymous OAuth linking recovers the owner from authenticated server state without the session cookie",async(ctx)=>{
 const actor=ctx.actor();
 const anonymous=await ctx.rawRequest({path:"/api/auth/sign-in/anonymous",method:"POST",json:{}});expect(anonymous.status).toBe(200);
 await ctx.setSocialProfile({email:ctx.uniqueEmail("anonymous-oauth"),sub:"anonymous-oauth-subject",name:"OAuth upgrade",emailVerified:true});
 const initiated=await actor.fetch(`${ctx.baseURL}/api/auth/sign-in/social`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({provider:"google",callbackURL:"/dashboard",additionalData:{serverContext:{anonymousUserId:"attacker-controlled"},oauthState:"attacker-state"}})});
 expect(initiated.status).toBe(200);const result=await initiated.json();const state=new URL(result.url).searchParams.get("state");expect(state).toBeString();
 const cookies=initiated.headers.getSetCookie().filter(cookie=>!cookie.startsWith("better-auth.session_")).map(cookie=>cookie.split(";")[0]).join("; ");
 expect(cookies).not.toBe("");
 const callback=await ctx.rawRequest({path:`/api/auth/callback/google?code=compat-code&state=${encodeURIComponent(state!)}`,headers:{cookie:cookies},redirect:"manual"});expect(callback.status).toBe(302);expect(callback.location).toBe("/dashboard");
 const session=await actor.client.getSession();expect(session.data.user.isAnonymous).toBe(false);
 const response=await fetch(`${ctx.baseURL}/__test/identity`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({action:"links"})});const links=await response.json();expect(links).toEqual([{anonymousId:anonymous.body.user.id,newId:session.data.user.id}]);
 return ctx.snapshot({callback,session,linked:links.length});
});
