import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
type Context = Parameters<Parameters<typeof compatScenario>[1]>[0];
async function events(ctx: Context, clear=false): Promise<any[]> {
  const response=await fetch(`${ctx.baseURL}/__test/otp-callbacks`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({action:clear?"clear":"get"})});
  expect(response.status).toBe(200);return response.json();
}
function post(ctx:Context,path:string,json:unknown,fail?:string) {
 return ctx.rawRequest({path:`/api/auth${path}`,method:"POST",json,headers:{"x-callback-tag":"typed-context",...(fail?{"x-callback-fail":fail}:{})}});
}
export function callbackScenarios(override:boolean) {
 compatScenario("email OTP callbacks receive parsed input and the active runtime through signup and delivery",async ctx=>{
  const email=ctx.uniqueEmail("otp-context");
  const signup=await post(ctx,"/sign-up/email",{email,password:"Password123!",name:"Callback Owner",customInput:"kept"});
  expect(signup.status,JSON.stringify(signup.body)).toBe(200);
  const signupEvents=await events(ctx);
  expect(signupEvents.map(event=>event.name)).toEqual(["email.generate","email.send"]);
  expect(signupEvents[0]).toMatchObject({header:"typed-context",requestPath:"/sign-up/email",basePath:"/api/auth",hasResponse:!override});
  expect(signupEvents[0].body).toMatchObject(override?{email,type:"email-verification"}:{email,name:"Callback Owner",customInput:"kept"});
  expect(signupEvents[1].data.userExists).toBe(true);
  await events(ctx,true);
  const sent=await post(ctx,"/email-otp/send-verification-otp",{email:email.toUpperCase(),type:"email-verification",discard:"unknown"});
  expect(sent.status).toBe(200);
  const sendEvents=await events(ctx);
  expect(sendEvents[0]).toMatchObject({path:"/email-otp/send-verification-otp",body:{email:email.toUpperCase(),type:"email-verification"},data:{email,type:"email-verification"},hasResponse:false});
  expect(sendEvents[0].body).not.toHaveProperty("discard");
  const generatorFailure=await post(ctx,"/email-otp/send-verification-otp",{email,type:"email-verification"},"generate");
  expect(generatorFailure.status).toBe(400);expect(generatorFailure.body).toMatchObject({code:"CALLBACK_REJECTED"});
  const senderFailure=await post(ctx,"/email-otp/request-password-reset",{email,discard:true},"email-send");
  expect(senderFailure.status).toBe(200);
  await events(ctx,true);
  const newEmail=ctx.uniqueEmail("otp-context-destination");
  const change=await post(ctx,"/email-otp/request-email-change",{newEmail,discard:true});
  expect(change.status).toBe(200);
  const changeEvents=await events(ctx);
  expect(changeEvents[0]).toMatchObject({name:"email.generate",body:{newEmail},sessionEmail:email,data:{email:newEmail,type:"change-email"}});
  expect(changeEvents[0].body).not.toHaveProperty("discard");
  let overridden=null;
  let overriddenFailure=null;
  if(override){
   await events(ctx,true);
   overridden=await post(ctx,"/send-verification-email",{email,callbackURL:"/"});
   expect(overridden.status).toBe(200);
   const dispatched=await events(ctx);
   expect(dispatched[0]).toMatchObject({path:"/email-otp/send-verification-otp",requestPath:"/send-verification-email",body:{email,type:"email-verification"},header:"typed-context"});
   overriddenFailure=await post(ctx,"/send-verification-email",{email},"generate");
   expect(overriddenFailure.status).toBe(200);
  }
  return {signup,sent,signupEvents,sendEvents,generatorFailure,senderFailure,change,changeEvents,overridden,overriddenFailure,finalEvents:await events(ctx)};
 });
 compatScenario("phone callbacks use the typed store and preserve each callback error boundary",async ctx=>{
  const phone="+15551234991";
  await events(ctx,true);
  const sendFailure=await post(ctx,"/phone-number/send-otp",{phoneNumber:phone,discard:"unknown"},"phone-send");
  expect(sendFailure.status).toBe(400);expect(sendFailure.body).toMatchObject({code:"CALLBACK_REJECTED"});
  const firstEvents=await events(ctx);
  expect(firstEvents[0]).toMatchObject({name:"phone.send",body:{phoneNumber:phone},data:{userExists:false},header:"typed-context"});
  expect(firstEvents[0].body).not.toHaveProperty("discard");
  const invalid=await post(ctx,"/phone-number/verify",{phoneNumber:phone,code:"invalid"});
  expect(invalid.status).toBe(400);expect(invalid.body).toMatchObject({code:"INVALID_OTP"});
  const verifyFailure=await post(ctx,"/phone-number/verify",{phoneNumber:phone,code:"246810"},"phone-verify");
  expect(verifyFailure.status).toBe(400);expect(verifyFailure.body).toMatchObject({code:"CALLBACK_REJECTED"});
  const hookFailure=await post(ctx,"/phone-number/verify",{phoneNumber:phone,code:"246810",customInput:"kept",disableSession:true},"verified");
  expect(hookFailure.status).toBe(400);expect(hookFailure.body).toMatchObject({code:"CALLBACK_REJECTED"});
  const verified=await post(ctx,"/phone-number/verify",{phoneNumber:phone,code:"246810",disableSession:true});
  expect(verified.status,JSON.stringify(verified.body)).toBe(200);
  const resetFailure=await post(ctx,"/phone-number/request-password-reset",{phoneNumber:phone,discard:true},"phone-reset");
  expect(resetFailure.status).toBe(200);
  const guard=await post(ctx,"/update-user",{phoneNumber:"+15551234000"});
  expect(guard.status).toBe(400);expect(guard.body).toMatchObject({code:"PHONE_NUMBER_CANNOT_BE_UPDATED"});
  const email=ctx.uniqueEmail("unverified-phone-context");
  const unverified=await post(ctx,"/sign-up/email",{email,name:"Unverified Phone",password:"Password123!",phoneNumber:"+15551234992"});
  expect(unverified.status).toBe(200);
  const signInFailure=await post(ctx,"/sign-in/phone-number",{phoneNumber:"+15551234992",password:"Password123!"},"phone-send");
  expect(signInFailure.status).toBe(401);expect(signInFailure.body).toMatchObject({code:"PHONE_NUMBER_NOT_VERIFIED"});
  const observed=await events(ctx);
  expect(observed.find(event=>event.name==="phone.verified").data.persistedVerified).toBe(true);
  return {sendFailure,invalid,verifyFailure,hookFailure,verified,resetFailure,guard,unverified,signInFailure,observed};
 });
}
