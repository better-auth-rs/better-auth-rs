import {Database} from "bun:sqlite";
import {betterAuth} from "better-auth";
import {apiKey} from "@better-auth/api-key";
import {getMigrations} from "better-auth/db/migration";
function deferred(){let resolve!:()=>void;const promise=new Promise<void>(done=>{resolve=done});return {promise,resolve};}
export const endpoints=["get","list","update","verify"] as const;
export const modes=[["default","resolve"],["default","reject"],["handler","resolve"],["handler","reject"],["handler-throw","reject"]] as const;
export async function runCase(endpoint:string,backend:string,scheduling:string,result:string){
 const db=new Database(":memory:"),entries=new Map<string,string>();
 const secondary={async get(key:string){return entries.get(key)??null;},async set(key:string,value:string){entries.set(key,value);},async delete(key:string){entries.delete(key);},async getAndDelete(key:string){const value=entries.get(key)??null;entries.delete(key);return value;}};
 const events:string[]=[],logs:any[]=[],tasks:Promise<unknown>[]=[];const gate=deferred(),entered=deferred();let done=false,started=0;
 const config:any={enableMetadata:true,storage:backend==="database"?"database":"secondary-storage",fallbackToDatabase:backend==="fallback",rateLimit:{enabled:false}};
 const options:any={database:db,baseURL:"http://localhost:3000",secret:"api-key-metadata-contract-secret-longer-than-thirty-two",rateLimit:{enabled:false},secondaryStorage:secondary,session:{storeSessionInDatabase:true},
  emailAndPassword:{enabled:true,password:{hash:async()=>"fixture",verify:async()=>true}},plugins:[apiKey(config)],
  logger:{level:"warn",log:(_:any,message:string,...args:any[])=>{if(message.startsWith("Failed to migrate double-stringified metadata")){events.push("migration:warning");logs.push({message:"migration-warning",error:args[0]?.message});}else if(message.startsWith("Failed to run background task")){events.push("handler:warning");logs.push({message,error:args[0]?.message});}}}};
 if(scheduling!=="default")options.advanced={backgroundTasks:{handler:(task:Promise<unknown>)=>{events.push("handler");tasks.push(task);if(scheduling==="handler-throw")throw new Error("handler-sync");}}};
 await(await getMigrations(options)).runMigrations();const auth=betterAuth(options);const signup=await auth.api.signUpEmail({body:{name:"Owner",email:"owner@example.com",password:"fixture-password"},asResponse:true});const user=(await signup.json()).user;
 const cookie=signup.headers.getSetCookie().map(value=>value.split(";")[0]).join("; ");
 const keys=[];for(const name of ["one","two"])keys.push(await auth.api.createApiKey({body:{userId:user.id,name,metadata:{legacy:name}}}));
 for(const key of keys){if(backend!=="cache")db.query("UPDATE apikey SET metadata=? WHERE id=?").run(JSON.stringify(JSON.stringify({legacy:key.name})),key.id);}
 for(const [name,text]of entries){if(name.startsWith("api-key:")&&!name.startsWith("api-key:by-ref:")){const value=JSON.parse(text);value.metadata=JSON.stringify({legacy:value.name});entries.set(name,JSON.stringify(value));}}
 const ctx=await auth.$context,original=ctx.adapter.update.bind(ctx.adapter);
 ctx.adapter.update=(async(input:any)=>{if(input.model!=="apikey"||!("metadata"in input.update))return original(input);const id=input.where.find((entry:any)=>entry.field==="id").value;const name=keys.find(key=>key.id===id)?.name;events.push(`migration:start:${name}`);if(++started===(endpoint==="list"?2:1))entered.resolve();await gate.promise;events.push(`migration:released:${name}`);if(result==="reject")throw new Error("migration-error");return original(input);}) as any;
 const snapshot=()=>({database:db.query("SELECT metadata FROM apikey ORDER BY name").all().map((row:any)=>JSON.parse(row.metadata)),cache:keys.map(key=>{const value=entries.get(`api-key:by-id:${key.id}`);return value?JSON.parse(value).metadata:null;})});
 const operation=(async()=>{try{let value:any;if(endpoint==="get")value=await auth.api.getApiKey({query:{id:keys[0].id},headers:{cookie}});else if(endpoint==="list")value=await auth.api.listApiKeys({headers:{cookie}});else if(endpoint==="update")value=await auth.api.updateApiKey({body:{keyId:keys[0].id,name:"one"},headers:{cookie}});else value=await auth.api.verifyApiKey({body:{key:keys[0].key}});return endpoint==="list"?value.apiKeys.map((key:any)=>key.metadata):[endpoint==="verify"?value.key.metadata:value.metadata];}finally{done=true;events.push("response");}})();
 const migrates=backend!=="cache";if(migrates)await entered.promise;
 if(!migrates||(endpoint==="list"&&scheduling!=="default"))await operation;
 const respondedBeforeRelease=done,storedBeforeRelease=snapshot();events.push("gate:release");gate.resolve();const metadata=await operation;
 const taskStates=(await Promise.allSettled(tasks)).map(task=>task.status);const storedAfterResponse=snapshot();db.close();
 return {endpoint,backend,scheduling,result,respondedBeforeRelease,storedBeforeRelease,storedAfterResponse,metadata,events,logs,taskStates};
}
