import {Database} from "bun:sqlite";
import {betterAuth} from "better-auth";
import {getMigrations} from "better-auth/db/migration";
function deferred(){let resolve!:()=>void;const promise=new Promise<void>(done=>{resolve=done});return {promise,resolve};}
export const modes=[["default","resolve"],["default","reject"],["handler","resolve"],["handler","reject"],["handler-throw","reject"],["handler","immediate-reject"],["handler-throw","immediate-reject"],["handler","sync-throw"]] as const;
export async function runCase(scheduling:string,result:string){
 const db=new Database(":memory:"),events:string[]=[],logs:any[]=[],tasks:Promise<unknown>[]=[];
 const entered=deferred(),gate=deferred();let done=false;
 const options:any={database:db,baseURL:"http://localhost:3000",secret:"rate-cleanup-contract-secret-longer-than-thirty-two",
  rateLimit:{enabled:true,storage:"database",customRules:{"/ok":{window:0,max:1}}},
  logger:{level:"error",log:(_:unknown,message:any,...args:any[])=>{if(message==="Error pruning rate limit rows"||message.startsWith("Failed to run background task")){events.push(`log:${args[0]?.message}`);logs.push({message,error:args[0]?.message});}}}};
 if(scheduling!=="default")options.advanced={backgroundTasks:{handler:(task:Promise<unknown>)=>{events.push("handler");tasks.push(task);if(scheduling==="handler-throw")throw new Error("handler-sync");}}};
 await(await getMigrations(options)).runMigrations();const auth=betterAuth(options);
 const request=()=>new Request("http://localhost:3000/api/auth/ok",{headers:{"x-forwarded-for":"192.0.2.77"}});
 await auth.handler(request());
 db.query("insert into rateLimit (id,key,count,lastRequest) values (?,?,?,?)").run("old","old",1,0);
 const ctx=await auth.$context;const original=ctx.adapter.deleteMany.bind(ctx.adapter);
 ctx.adapter.deleteMany=((input:any)=>{events.push("cleanup:start");entered.resolve();if(result==="sync-throw")throw new Error("cleanup-sync");
  if(result==="immediate-reject")return Promise.reject(new Error("cleanup-async"));
  return (async()=>{await gate.promise;events.push("cleanup:released");if(result==="reject")throw new Error("cleanup-async");return original(input);})();}) as any;
 const snapshot=()=>({rows:(db.query("select count(*) as count from rateLimit").get()as any).count,reset:(db.query("select count from rateLimit where key != 'old'").get()as any).count});
 const operation=(async()=>{try{const response=await auth.handler(request());return {status:response.status,thrown:null};}catch(error:any){return {status:null,thrown:error.message};}finally{done=true;events.push("response");}})();
 await entered.promise;if(scheduling!=="default")await operation;
 const respondedBeforeRelease=done,storedBeforeRelease=snapshot();events.push("gate:release");gate.resolve();
 const status=await operation;const taskStates=(await Promise.allSettled(tasks)).map(value=>value.status);const storedAfterResponse=snapshot();
 db.close();return {scheduling,result,respondedBeforeRelease,storedBeforeRelease,storedAfterResponse,status,events,logs,taskStates};
}
