import {test,expect} from "bun:test";
import {Database} from "bun:sqlite";
import {betterAuth} from "better-auth";
import {apiKey} from "@better-auth/api-key";
import {getMigrations} from "better-auth/db/migration";

for(const scenario of ["empty","current","page","mixed-cache"])test(`list migration boundary: ${scenario}`,async()=>{
 const database=new Database(":memory:"),cache=new Map<string,string>(),tasks:Promise<unknown>[]=[],updates:any[]=[];
 const secondaryStorage={async get(key:string){return cache.get(key)??null;},async set(key:string,value:string){cache.set(key,value);},async delete(key:string){cache.delete(key);}};
 const configurations:any[]=scenario==="mixed-cache"?[{configId:"cache",storage:"secondary-storage",enableMetadata:true},{configId:"db",storage:"database",enableMetadata:true}]:[{enableMetadata:true}];
 const options:any={database,secondaryStorage,session:{storeSessionInDatabase:true},baseURL:"http://localhost:3000",secret:"api-key-metadata-pages-secret-with-at-least-thirty-two",
  emailAndPassword:{enabled:true,password:{hash:async()=>"fixture",verify:async()=>true}},plugins:[apiKey(scenario==="mixed-cache"?configurations:configurations[0])],rateLimit:{enabled:false},advanced:{backgroundTasks:{handler:(task:Promise<unknown>)=>{tasks.push(task);}}}};
 await(await getMigrations(options)).runMigrations();const auth=betterAuth(options);
 const signup=await auth.api.signUpEmail({body:{name:"Owner",email:"owner@example.com",password:"fixture-password"},asResponse:true});const user=(await signup.json()).user;
 const headers={cookie:signup.headers.getSetCookie().map(value=>value.split(";")[0]).join("; ")},keys:any[]=[];
 if(scenario!=="empty")for(const name of ["one","two"])keys.push(await auth.api.createApiKey({body:{userId:user.id,name,metadata:{legacy:name},...(scenario==="mixed-cache"?{configId:"cache"}:{})}}));
 if(scenario==="page")for(const key of keys)database.query("UPDATE apikey SET metadata=? WHERE id=?").run(JSON.stringify(JSON.stringify({legacy:key.name})),key.id);
 if(scenario==="mixed-cache")for(const [name,text]of cache)if(name.startsWith("api-key:")&&!name.startsWith("api-key:by-ref:")){const key=JSON.parse(text);key.metadata=JSON.stringify({legacy:key.name});cache.set(name,JSON.stringify(key));}
 const ctx=await auth.$context,original=ctx.adapter.update.bind(ctx.adapter);
 ctx.adapter.update=(async(input:any)=>{if(input.model==="apikey"&&"metadata"in input.update)updates.push({name:keys.find(key=>key.id===input.where[0].value)?.name,metadata:input.update.metadata});return original(input);})as any;
 const result=await auth.api.listApiKeys({headers,query:scenario==="page"?{offset:1,limit:1,sortBy:"name"}:scenario==="mixed-cache"?{configId:"cache"}:{}});
 await Promise.all(tasks);
 expect(tasks).toHaveLength(1);
 expect(updates).toEqual(scenario==="page"?[{name:"two",metadata:{legacy:"two"}}]:scenario==="mixed-cache"?[{name:"one",metadata:{legacy:"one"}},{name:"two",metadata:{legacy:"two"}}]:[]);
 expect(result.apiKeys.map(key=>key.metadata)).toEqual(scenario==="empty"?[]:scenario==="page"?[{legacy:"two"}]:[{legacy:"one"},{legacy:"two"}]);
 if(scenario==="page")expect(database.query("SELECT metadata FROM apikey ORDER BY name").all().map((row:any)=>JSON.parse(row.metadata))).toEqual([JSON.stringify({legacy:"one"}),{legacy:"two"}]);
 database.close();
});
