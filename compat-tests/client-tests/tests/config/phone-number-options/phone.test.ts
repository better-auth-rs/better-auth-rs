import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
import {post,control,send,error} from "../phone-number/helpers";
compatScenario("required phone verification blocks password login and disabled signup does not create users",async(ctx)=>{
 const email=ctx.uniqueEmail("phone-requires-proof"),phoneNumber="+15555550105";
 const signup=await ctx.actor().client.signUp.email({email,name:"Existing",password:"Password123!"});expect(signup.error).toBeNull();
 await control(ctx,{action:"phone",email,phoneNumber,verified:false});
 const login=await post(ctx,"/sign-in/phone-number",{phoneNumber,password:"Wrong123!"},"other");error(login,401,"PHONE_NUMBER_NOT_VERIFIED");
 const messages=await control(ctx,{phoneNumber});expect(messages.at(-1).code).toMatch(/^\d{6}$/);
 const verified=await post(ctx,"/phone-number/verify",{phoneNumber,code:messages.at(-1).code,disableSession:true},"other");expect(verified.status).toBe(200);expect(verified.body.token).toBeNull();
 const ready=await post(ctx,"/sign-in/phone-number",{phoneNumber,password:"Password123!"},"other");expect(ready.status).toBe(200);expect(ready.body.user.id).toBe(signup.data.user.id);
 const unknown="+15555550106";const code=await send(ctx,unknown);const disabled=await post(ctx,"/phone-number/verify",{phoneNumber:unknown,code});error(disabled,500,"FAILED_TO_UPDATE_USER");
 return ctx.snapshot({login,verified,ready,disabled});
});
