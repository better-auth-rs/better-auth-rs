import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
async function native(ctx:Context,body:any){
 const response=await fetch(`${ctx.baseURL}/__test/email-otp-native`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
 return {status:response.status,body:await response.json()};
}
function summary(body:any){const {expiresAt,...stable}=body;return stable;}
export function nativeScenarios(mode:string){
 const hashed=mode==="hash"||mode==="custom-hash";
 compatScenario("native OTP create/get support all purposes and arbitrary strings without sending or exposing HTTP routes",async ctx=>{
  const missing=await native(ctx,{action:"get"});expect(missing).toEqual({status:200,body:{otp:null}});
  const outputs=[];
  for(const type of ["sign-in","email-verification","forget-password","change-email"]){
   const created=await native(ctx,{action:"create",email:"NOT-AN-EMAIL",type});expect(created.status).toBe(200);expect(created.body).toMatch(/^\d{6}:tail$/);
   const get=await native(ctx,{action:"get",email:"not-an-email",type});
   expect(get).toEqual(hashed?{status:400,body:{message:"OTP is hashed, cannot return the plain text OTP"}}:{status:200,body:{otp:created.body}});
   outputs.push({created,get});
  }
  const state=await native(ctx,{action:"inspect",email:"NOT-AN-EMAIL",type:"change-email"});expect(state.status).toBe(200);expect(state.body.generated).toBe(4);expect(state.body.sent).toBe(0);expect(state.body.attempts).toBe(0);
  for(const event of state.body.events)expect(event).toMatchObject({data:{email:"not-an-email"},body:{email:"NOT-AN-EMAIL"},hasRequest:false,path:"virtual:"});
  if(mode==="custom-hash")expect(state.body.encoded).toBe(4);
  const createHTTP=await ctx.rawRequest({path:"/api/auth/email-otp/create-verification-otp",method:"POST",json:{email:"not-an-email",type:"sign-in"}});expect(createHTTP.status).toBe(404);
  const getHTTP=await ctx.rawRequest({path:"/api/auth/email-otp/get-verification-otp?email=not-an-email&type=sign-in"});expect(getHTTP.status).toBe(404);
  return {missing,outputs,state:summary(state.body),createHTTP,getHTTP};
 });
 compatScenario("native reads preserve attempts and expiry while creates ignore resend reuse",async ctx=>{
  const email=ctx.uniqueEmail("native-otp");const first=await native(ctx,{action:"create",email});expect(first.status).toBe(200);
  const wrong=await ctx.rawRequest({path:"/api/auth/email-otp/check-verification-otp",method:"POST",json:{email,type:"sign-in",otp:"wrong"}});expect(wrong.status).toBe(400);expect(wrong.body).toMatchObject({code:"INVALID_OTP"});
  const before=await native(ctx,{action:"inspect",email});expect(before.body.attempts).toBe(1);
  const read=await native(ctx,{action:"get",email});expect(read.status).toBe(hashed?400:200);
  const after=await native(ctx,{action:"inspect",email});expect(after.body.attempts).toBe(1);expect(after.body.expiresAt).toBe(before.body.expiresAt);
  // Upstream selects the newest record by createdAt; require a distinct clock tick.
  await Bun.sleep(2);
  const second=await native(ctx,{action:"create",email});expect(second.status).toBe(200);expect(second.body).not.toBe(first.body);
  const live=await native(ctx,{action:"get",email});expect(live).toEqual(hashed?{status:400,body:{message:"OTP is hashed, cannot return the plain text OTP"}}:{status:200,body:{otp:second.body}});
  const current=await native(ctx,{action:"inspect",email});expect(current.body.attempts).toBe(0);expect(current.body.sent).toBe(0);
  await native(ctx,{action:"expire",email});
  const expired=await native(ctx,{action:"get",email});expect(expired).toEqual({status:200,body:{otp:null}});
  return {first,wrong,read,before:summary(before.body),after:summary(after.body),second,live,current:summary(current.body),expired};
 });
 compatScenario("native generator and custom protection errors propagate without creating a record",async ctx=>{
  const email=ctx.uniqueEmail("native-failure");
  const failure=await native(ctx,{action:"create",email,fail:"generate"});expect(failure).toEqual({status:400,body:{code:"NATIVE_OTP_REJECTED",message:"Native OTP rejected"}});
  expect((await native(ctx,{action:"get",email,fail:""})).body).toEqual({otp:null});
  let encode=null,decode=null;
  if(mode.startsWith("custom-")){
   encode=await native(ctx,{action:"create",email,fail:"encode"});expect(encode.status).toBe(400);expect(encode.body.code).toBe("NATIVE_OTP_REJECTED");
   expect((await native(ctx,{action:"get",email,fail:""})).body).toEqual({otp:null});
  }
  const created=await native(ctx,{action:"create",email,fail:""});expect(created.status).toBe(200);
  if(mode==="custom-encrypted"){
   decode=await native(ctx,{action:"get",email,fail:"decode"});expect(decode.status).toBe(400);expect(decode.body.code).toBe("NATIVE_OTP_REJECTED");
   const recovered=await native(ctx,{action:"get",email,fail:""});expect(recovered.body).toEqual({otp:created.body});
  }
  const final=await native(ctx,{action:"inspect",email});expect(final.body.exists).toBe(true);expect(final.body.sent).toBe(0);
  return {failure,encode,decode,created,final:summary(final.body)};
 });
}
