import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
import {post,control,error,signed,sign,address} from "./helpers";
compatScenario("SIWE verifies real EIP-191 signatures and reuses one wallet owner across chains",async(ctx)=>{
 const request=await signed(ctx);const login=await post(ctx,"/siwe/verify",request);expect(login.status).toBe(200);expect(login.body.success).toBe(true);expect(login.body.user.walletAddress.toLowerCase()).toBe(address);expect(login.body.user.chainId).toBe(1);
 const session=await ctx.actor().client.getSession();expect(session.data.user.id).toBe(login.body.user.id);
 const replay=await post(ctx,"/siwe/verify",request);error(replay,401,"UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
 const another=await post(ctx,"/siwe/verify",await signed(ctx,{alias:true,chainId:137}));expect(another.status).toBe(200);expect(another.body.user.id).toBe(login.body.user.id);
 const repeat=await post(ctx,"/siwe/verify",await signed(ctx));expect(repeat.status).toBe(200);expect(repeat.body.user.id).toBe(login.body.user.id);
 const invalidDate=await post(ctx,"/siwe/verify",await signed(ctx,{extra:"\nExpiration Time: not-a-date"}));expect(invalidDate.status).toBe(200);expect(invalidDate.body.user.id).toBe(login.body.user.id);
 const wallets=await control(ctx,{action:"wallets"});expect(wallets).toHaveLength(2);expect(wallets.map((wallet:any)=>({chainId:wallet.chainId,isPrimary:wallet.isPrimary}))).toEqual([{chainId:1,isPrimary:true},{chainId:137,isPrimary:false}]);expect(wallets.every((wallet:any)=>wallet.userId===login.body.user.id)).toBe(true);
 return ctx.snapshot({login,session,replay,another,repeat,invalidDate,wallets});
});
compatScenario("SIWE rejects signed wrong domains, validity windows, altered signatures and nonce replay",async(ctx)=>{
 const wrongDomain=await signed(ctx,{domain:"attacker.example.com"});const domain=await post(ctx,"/siwe/verify",wrongDomain);error(domain,401,"UNAUTHORIZED_SIWE_MESSAGE_MISMATCH");
 const domainReplay=await post(ctx,"/siwe/verify",wrongDomain);error(domainReplay,401,"UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
 const expired=await post(ctx,"/siwe/verify",await signed(ctx,{extra:"\nExpiration Time: 2000-01-01T00:00:00.000Z"}));error(expired,401,"UNAUTHORIZED_SIWE_MESSAGE_EXPIRED");
 const dateOnly=await post(ctx,"/siwe/verify",await signed(ctx,{extra:"\nExpiration Time: 2000-01-01"}));error(dateOnly,401,"UNAUTHORIZED_SIWE_MESSAGE_EXPIRED");
 const rfcDate=await post(ctx,"/siwe/verify",await signed(ctx,{extra:"\nExpiration Time: Sat, 01 Jan 2000 00:00:00 +0000"}));error(rfcDate,401,"UNAUTHORIZED_SIWE_MESSAGE_EXPIRED");
 const future=await post(ctx,"/siwe/verify",await signed(ctx,{extra:"\nNot Before: 2099-01-01T00:00:00.000Z"}));error(future,401,"UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID");
 const futureDate=await post(ctx,"/siwe/verify",await signed(ctx,{extra:"\nNot Before: 2099-01-01"}));error(futureDate,401,"UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID");
 const request=await signed(ctx);const otherKey=new Uint8Array(32);otherKey[31]=2;
 const signature=await post(ctx,"/siwe/verify",{...request,signature:sign(request.message,otherKey)});expect(signature.status).toBe(401);expect(signature.body.message).toBe("Unauthorized: Invalid SIWE signature");
 const replay=await post(ctx,"/siwe/verify",request);error(replay,401,"UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
 const session=await ctx.actor().client.getSession();expect(session.data).toBeNull();
 return ctx.snapshot({domain,domainReplay,expired,dateOnly,rfcDate,future,futureDate,signature,replay,session});
});
compatScenario("SIWE validates the strict HTTP body before creating or consuming a nonce",async(ctx)=>{
 const unknown=await post(ctx,"/siwe/nonce",{unexpected:true});expect(unknown.status).toBe(400);
 const wrongType=await post(ctx,"/siwe/verify",{message:1,signature:false});expect(wrongType.status).toBe(400);
 const empty=await post(ctx,"/siwe/verify",{message:"",signature:""});expect(empty.status).toBe(400);
 const malformed=await ctx.rawRequest({path:"/api/auth/siwe/verify",method:"POST",body:"{",headers:{"content-type":"application/json"}});expect(malformed.status).toBe(400);
 const extra=await post(ctx,"/siwe/verify",{...await signed(ctx),extra:true});expect(extra.status).toBe(400);
 return ctx.snapshot({unknown,wrongType,empty,malformed,extra});
});
