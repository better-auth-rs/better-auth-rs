import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
import {post,control,send,error} from "./helpers";
compatScenario("phone OTP signup creates a reusable password account through reset",async(ctx)=>{
 const phoneNumber="+15555550101";
 const code=await send(ctx,phoneNumber);
 const wrong=await post(ctx,"/phone-number/verify",{phoneNumber,code:"wrong"});error(wrong,400,"INVALID_OTP");
 const verified=await post(ctx,"/phone-number/verify",{phoneNumber,code});expect(verified.status).toBe(200);expect(verified.body.user).toMatchObject({phoneNumber,phoneNumberVerified:true});expect(verified.body.token).toBeString();
 const replay=await post(ctx,"/phone-number/verify",{phoneNumber,code});error(replay,400,"OTP_NOT_FOUND");
 const session=await ctx.actor().client.getSession();expect(session.data.user.id).toBe(verified.body.user.id);
 const resetCode=await send(ctx,phoneNumber,"reset");
 const reset=await post(ctx,"/phone-number/reset-password",{phoneNumber,otp:resetCode,newPassword:"Updated123!"});expect(reset.status).toBe(200);expect(reset.body).toEqual({status:true});
 const bad=await post(ctx,"/sign-in/phone-number",{phoneNumber,password:"Wrong123!"},"other");error(bad,401,"INVALID_PHONE_NUMBER_OR_PASSWORD");
 const login=await post(ctx,"/sign-in/phone-number",{phoneNumber,password:"Updated123!",rememberMe:false},"other");expect(login.status).toBe(200);expect(login.body.user.id).toBe(verified.body.user.id);
 const remove=await post(ctx,"/update-user",{phoneNumber:null});expect(remove.status).toBe(200);
 const removed=await ctx.actor().client.getSession({query:{disableCookieCache:true}});expect(removed.data.user).toMatchObject({phoneNumber:null,phoneNumberVerified:false});
 return ctx.snapshot({wrong,verified,replay,session,reset,bad,login,remove,removed});
});
compatScenario("phone OTP attempts expire and exhausted records cannot authenticate",async(ctx)=>{
 const phoneNumber="+15555550102";
 const code=await send(ctx,phoneNumber);
 const failures=[];for(let index=0;index<3;index++){const result=await post(ctx,"/phone-number/verify",{phoneNumber,code:"wrong"});error(result,400,"INVALID_OTP");failures.push(result);}
 const exhausted=await post(ctx,"/phone-number/verify",{phoneNumber,code});error(exhausted,403,"TOO_MANY_ATTEMPTS");
 const replay=await post(ctx,"/phone-number/verify",{phoneNumber,code});error(replay,400,"OTP_NOT_FOUND");
 const expiredCode=await send(ctx,phoneNumber);await control(ctx,{action:"expire",identifier:phoneNumber});
 const expired=await post(ctx,"/phone-number/verify",{phoneNumber,code:expiredCode});error(expired,400,"OTP_EXPIRED");
 const invalid=await post(ctx,"/phone-number/send-otp",{phoneNumber:"not-a-phone"});error(invalid,400,"INVALID_PHONE_NUMBER");
 const missing=await post(ctx,"/phone-number/request-password-reset",{phoneNumber:"+15555550999"});expect(missing.status).toBe(200);expect(await control(ctx,{phoneNumber:"+15555550999"})).toEqual([]);
 return ctx.snapshot({failures,exhausted,replay,expired,invalid,missing});
});
compatScenario("phone verification binds only the authenticated owner and consumes OTP before mutation",async(ctx)=>{
 const phoneNumber="+15555550103";const code=await send(ctx,phoneNumber);
 const denied=await post(ctx,"/phone-number/verify",{phoneNumber,code,updatePhoneNumber:true});error(denied,401,"USER_NOT_FOUND");
 const replay=await post(ctx,"/phone-number/verify",{phoneNumber,code,updatePhoneNumber:true});error(replay,400,"OTP_NOT_FOUND");
 const signup=await ctx.actor().client.signUp.email({email:ctx.uniqueEmail("phone-owner"),name:"Phone owner",password:"Password123!"});expect(signup.error).toBeNull();
 const next=await send(ctx,phoneNumber);const bound=await post(ctx,"/phone-number/verify",{phoneNumber,code:next,updatePhoneNumber:true});expect(bound.status).toBe(200);expect(bound.body.user.id).toBe(signup.data.user.id);
 const protectedUpdate=await post(ctx,"/update-user",{phoneNumber:"+15555550104"});error(protectedUpdate,400,"PHONE_NUMBER_CANNOT_BE_UPDATED");
 return ctx.snapshot({denied,replay,bound,protectedUpdate});
});
compatScenario("phone request validation rejects malformed input before sending OTP",async(ctx)=>{
 const missing=await post(ctx,"/phone-number/verify",{});expect(missing.status).toBe(400);
 const invalid=await post(ctx,"/phone-number/verify",{phoneNumber:17,code:false,disableSession:"no"});expect(invalid.status).toBe(400);
 const malformed=await ctx.rawRequest({path:"/api/auth/phone-number/send-otp",method:"POST",body:"{",headers:{"content-type":"application/json"}});expect(malformed.status).toBe(400);
 return ctx.snapshot({missing,invalid,malformed});
});
