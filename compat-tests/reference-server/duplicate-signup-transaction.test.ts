import {Database} from "bun:sqlite";
import {betterAuth} from "better-auth";
import {getMigrations} from "better-auth/db/migration";
import {getCurrentAuthEndpointContext} from "@better-auth/core/context";
import {test,expect} from "bun:test";
for(const mode of ["resolve","reject","rollback"])test(`duplicate signup active transaction ${mode}`,async()=>{
 const db=new Database(":memory:"),events:string[]=[];
 const options:any={database:db,baseURL:"http://localhost:3000",secret:"duplicate-transaction-contract-secret-longer-than-thirty-two",rateLimit:{enabled:false},
 emailAndPassword:{enabled:true,autoSignIn:false,password:{hash:async()=>"fixture",verify:async()=>true},
 onExistingUserSignUp:()=>{const ctx=getCurrentAuthEndpointContext();events.push("sender:start");return(async()=>{await ctx.context.internalAdapter.createVerificationValue({identifier:"duplicate",value:"value",expiresAt:new Date(Date.now()+60000)});events.push("sender:created");if(mode==="reject")throw new Error("sender-async");})();},
 customSyntheticUser:(data:any)=>{events.push("synthetic");if(mode==="rollback")throw new Error("synthetic-error");return {...data.coreFields,id:data.id};}},
 databaseHooks:{verification:{create:{before:async()=>{events.push("verification:before");},after:async()=>{events.push("verification:after");}}}},
 logger:{level:"error",log:(_:any,message:string)=>{if(message.startsWith("Failed to run background task"))events.push("log");}}};
 await(await getMigrations(options)).runMigrations();const auth=betterAuth(options);
 const body={name:"Owner",email:"owner@example.com",password:"fixture-password"};await auth.api.signUpEmail({body});
 let failure:string|null=null;try{await auth.api.signUpEmail({body});}catch(error:any){failure=error.message;}events.push("response");
 expect(failure).toBe(mode==="rollback"?"synthetic-error":null);
 expect(events).toEqual(["sender:start","verification:before","sender:created",...(mode==="reject"?["log"]:[]),"synthetic",...(mode==="rollback"?[]:["verification:after"]),"response"]);
 expect((db.query("select count(*) as count from verification").get()as any).count).toBe(mode==="rollback"?0:1);
 db.close();
});
