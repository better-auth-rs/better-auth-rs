import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
import {post,signed,address} from "../siwe/helpers";
compatScenario("SIWE email mode never links a wallet to an existing email account",async(ctx)=>{
 const email=ctx.uniqueEmail("existing-wallet-email");const signup=await ctx.actor("email").client.signUp.email({email,name:"Original owner",password:"Password123!"});expect(signup.error).toBeNull();
 const missing=await post(ctx,"/siwe/verify",await signed(ctx));expect(missing.status).toBe(400);expect(missing.body.code).toBe("VALIDATION_ERROR");
 const request=await signed(ctx);const login=await post(ctx,"/siwe/verify",{...request,email});expect(login.status).toBe(200);expect(login.body.user.id).not.toBe(signup.data.user.id);
 const session=await ctx.actor().client.getSession();expect(session.data.user.email.toLowerCase()).toBe(`${address}@siwe.placeholder.invalid`);
 const original=await ctx.actor("email").client.getSession();expect(original.data.user.id).toBe(signup.data.user.id);
 return ctx.snapshot({missing,login,session,original});
});
