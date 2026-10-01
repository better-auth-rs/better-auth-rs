import {test,expect} from "bun:test";
import {betterAuth} from "better-auth";
import {admin} from "better-auth/plugins";
import {Database} from "bun:sqlite";
import {getMigrations} from "better-auth/db/migration";
for(const database of [false,true])test(`Admin ${database?'SQLite':'memory'} projects one page before an unpaged count`,async()=>{
 const events:string[]=[];let fail=false;const adminUserIds:string[]=[];
 const auth=betterAuth({baseURL:"http://count.example",secret:"reference-admin-count-secret-more-than-32",...(database?{database:new Database(":memory:")} :{}),
   logger:{disabled:true},emailAndPassword:{enabled:true,password:{hash:async(value)=>value,verify:async({password,hash})=>password===hash}},
   user:{additionalFields:{note:{type:"string",required:false,transform:{output(value){events.push(`output:${value}`);if(fail&&value==="two")throw new Error("list projection failed");return value;}}}}},
   plugins:[admin({adminUserIds})]});
 if(database) await (await getMigrations(auth.options)).runMigrations();
 const signup=await auth.api.signUpEmail({body:{email:"owner@count.example",name:"Owner",password:"password123"},returnHeaders:true});adminUserIds.push(signup.response.user.id);
 const headers=new Headers({cookie:signup.headers.getSetCookie().map(value=>value.split(";",1)[0]).join("; ")});
 const ctx=await auth.$context;
 for(const [name,note] of [["Included A","one"],["Included B","two"],["Excluded","three"]])await ctx.internalAdapter.createUser({name,email:`${name.replaceAll(' ','-')}@count.example`,emailVerified:false,note});
 for(const name of ["findMany","count"] as const){const fn=ctx.adapter[name].bind(ctx.adapter);ctx.adapter[name]=((...args:any[])=>{events.push(name);return (fn as any)(...args)}) as any;}
 const query={searchField:"name" as const,searchValue:"Included",sortBy:"name",limit:1,offset:1};events.length=0;
 const result=await auth.api.listUsers({headers,query});expect(result.users.map(user=>user.name)).toEqual(["Included B"]);expect(result.total).toBe(2);
 expect(events.filter(value=>value==="findMany"||value==="count"||value==="output:two"||value==="output:one"||value==="output:three")).toEqual(["findMany","output:two","count"]);
 events.length=0;fail=true;const rejected=await auth.api.listUsers({headers,query});expect(rejected.users).toEqual([]);expect(rejected.total).toBe(0);expect(events.includes("count")).toBe(false);
});
