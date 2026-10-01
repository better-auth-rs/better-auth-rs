import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

async function post(ctx: any, path: string, body: any, headers: Record<string, string> = {}) {
  return fetch(`${ctx.baseURL}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: ctx.baseURL, ...headers }, body: JSON.stringify(body) });
}
async function call(ctx: any, mode: string, path: string, body: any, headers: Record<string, string> = {}) {
  return mode === "http" ? post(ctx, `/api/auth${path}`, body, headers) : post(ctx, "/__test/query-native", { path, method: "POST", body, headers });
}
async function clear(ctx: any) { await post(ctx, "/__test/body-events", {}); }
async function events(ctx: any) { return (await (await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events; }
function checkTrace(trace: any[], phases: string[], body: any, projected: any, mode: string) {
  expect(trace.map(event => event.phase)).toEqual(phases);
  for (const event of trace) {
    const raw = ["before", "plugin.before", "after"].includes(event.phase);
    expect(event.body).toEqual(raw ? body : projected);
    expect(event.request).toBe(mode === "http");
    expect(event.requestBody).toBe(mode === "http" ? JSON.stringify(body) : null);
  }
}
for (const mode of ["http", "native"]) {
  compatScenario(`${mode}: Username, transfer-token, and verification schemas reject invalid inputs before effects`, async ctx => {
    const cases: [string, any, string][] = [
      ["/sign-in/username", { username: null, password: 4, rememberMe: "false" }, '[body.username] Invalid input: expected string, received null; [body.password] Invalid input: expected string, received number; [body.rememberMe] Invalid input: expected boolean, received string'],
      ["/is-username-available", { username: [] }, '[body.username] Invalid input: expected string, received array'],
      ["/one-time-token/verify", { token: false }, '[body.token] Invalid input: expected string, received boolean'],
      ["/multi-session/set-active", {}, '[body.sessionToken] Invalid input: expected string, received undefined'],
      ["/multi-session/revoke", { sessionToken: null }, '[body.sessionToken] Invalid input: expected string, received null'],
      ["/send-verification-email", { email: "invalid", unknown: "raw" }, '[body.email] Invalid email address'],
    ];
    const results=[];
    for(const [path,body,message] of cases){
      await clear(ctx);const response=await call(ctx,mode,path,body);expect(response.status).toBe(400);
      const value=await response.json();expect(value).toEqual({code:"VALIDATION_ERROR",message});
      const trace=await events(ctx);checkTrace(trace,["before","plugin.before","after"],body,body,mode);results.push({path,value,trace});
    }
    return results;
  });
  compatScenario(`${mode}: plugin handler inputs reach real credentials, senders, and session deletion`, async ctx => {
    const email=`plugin-schema-${mode}@query.example`,username=`plugin_${mode}`;
    const created=await post(ctx,"/api/auth/sign-up/email",{email,name:"Plugin schema",username,password:"fixture-password"});
    expect(created.status).toBe(200);const owner=await created.json();
    const headers={cookie:created.headers.getSetCookie().map(value=>value.split(";",1)[0]).join("; ")};
    await clear(ctx);
    const availableBody={username,unknown:"raw"};const available=await call(ctx,mode,"/is-username-available",availableBody);
    expect(available.status).toBe(200);expect(await available.json()).toEqual({available:false});
    const availableTrace=await events(ctx);checkTrace(availableTrace,["before","plugin.before","after"],availableBody,{username},mode);
    await clear(ctx);
    const signInBody={username,password:"fixture-password",unknown:"raw"};const signed=await call(ctx,mode,"/sign-in/username",signInBody);
    expect(signed.status).toBe(200);expect((await signed.json()).user.id).toBe(owner.user.id);
    const signInTrace=await events(ctx);checkTrace(signInTrace,["before","plugin.before","verify","session.before","session.after","after"],signInBody,{username,password:"fixture-password"},mode);
    await clear(ctx);
    const emailBody={email,callbackURL:"/verified",unknown:"raw"};const sent=await call(ctx,mode,"/send-verification-email",emailBody,headers);
    expect(sent.status).toBe(200);expect(await sent.json()).toEqual({status:true});
    const emailTrace=await events(ctx);checkTrace(emailTrace,["before","plugin.before","email.sender","after"],emailBody,{email,callbackURL:"/verified"},mode);
    const generation=await post(ctx,"/__test/query-native",{path:"/one-time-token/generate",headers});expect(generation.status).toBe(200);const {token}=await generation.json();
    await clear(ctx);
    const verifyBody={token,unknown:"raw"};const transferred=await call(ctx,mode,"/one-time-token/verify",verifyBody);expect(transferred.status).toBe(200);expect((await transferred.json()).user.id).toBe(owner.user.id);
    const verifyTrace=await events(ctx);checkTrace(verifyTrace,["before","plugin.before","after"],verifyBody,{token},mode);
    const replay=await call(ctx,mode,"/one-time-token/verify",verifyBody);expect(replay.status).toBe(400);
    await clear(ctx);
    const sessionBody={sessionToken:owner.token,unknown:"raw"};const active=await call(ctx,mode,"/multi-session/set-active",sessionBody,headers);expect(active.status).toBe(200);expect((await active.json()).user.id).toBe(owner.user.id);
    const activeTrace=await events(ctx);checkTrace(activeTrace,["before","plugin.before","after"],sessionBody,{sessionToken:owner.token},mode);
    await clear(ctx);
    const revoked=await call(ctx,mode,"/multi-session/revoke",sessionBody,headers);expect(revoked.status).toBe(200);expect(await revoked.json()).toEqual({status:true});
    const revokeTrace=await events(ctx);checkTrace(revokeTrace,["before","plugin.before","session.delete.before","session.delete.after","after"],sessionBody,{sessionToken:owner.token},mode);
    return JSON.parse(JSON.stringify({availableTrace,signInTrace,emailTrace,verifyTrace,activeTrace,revokeTrace}).replaceAll(owner.token,"<session-token>").replaceAll(token,"<one-time-token>"));
  });
}
