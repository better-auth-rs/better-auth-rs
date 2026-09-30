import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
compatScenario("anonymous deletion can be disabled without disabling account-link callback",async(ctx)=>{
 const signed=await ctx.rawRequest({path:"/api/auth/sign-in/anonymous",method:"POST",json:{}});expect(signed.status).toBe(200);
 const deleted=await ctx.rawRequest({path:"/api/auth/delete-anonymous-user",method:"POST",json:{}});expect(deleted.status).toBe(400);expect(deleted.body.code).toBe("DELETE_ANONYMOUS_USER_DISABLED");
 const signup=await ctx.actor().client.signUp.email({email:ctx.uniqueEmail("retained"),name:"Retained",password:"Password123!"});expect(signup.error).toBeNull();
 const response=await fetch(`${ctx.baseURL}/__test/identity`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({action:"links"})});const links=await response.json();expect(links).toEqual([{anonymousId:signed.body.user.id,newId:signup.data.user.id}]);
 return ctx.snapshot({deleted,signup,linked:links.length});
});
