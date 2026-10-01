import {Database} from "bun:sqlite";
import {betterAuth} from "better-auth";
import {organization} from "better-auth/plugins";
import {getMigrations} from "better-auth/db/migration";
import {getCurrentAuthEndpointContext, getCurrentAdapter} from "@better-auth/core/context";

export const endpoints = ["invite", "resend", "signup"] as const;
export const modes = [["default","resolve"],["default","reject"],["handler","resolve"],["handler","reject"],["handler","sync-throw"],["handler","void"],["handler-throw","reject"]] as const;
function deferred() {let resolve!:()=>void;const promise=new Promise<void>(done=>{resolve=done});return {promise,resolve};}
export async function runCase(endpoint: string, transport: "http"|"native", scheduling: string, sender: string) {
  const database=new Database(":memory:");
  const gate=deferred(),entered=deferred(),finished=deferred();
  const events:string[]=[],contexts:any[]=[],logs:any[]=[],tasks:Promise<unknown>[]=[];
  let armed=false,done=false;
  function capture(phase:string,data:any,request:Request|undefined) {
    const ctx=getCurrentAuthEndpointContext();
    contexts.push({phase,path:ctx.path,body:ctx.body,request:!!request,requestPath:request?new URL(request.url).pathname:null,
      email:endpoint==="signup"?data.user.email:data.email, role:data.role??null,inviter:data.inviter?.user.email??null});
  }
  function send(data:any,request:Request|undefined) {
    if(!armed)return;
    events.push("sender:start");capture("start",data,request);entered.resolve();
    if(sender==="sync-throw"){finished.resolve();throw new Error("sender-sync");}
    if(sender==="void"){events.push("sender:void");finished.resolve();return;}
    return (async()=>{
      await gate.promise;capture("released",data,request);events.push("sender:released");finished.resolve();
      if(sender==="reject")throw new Error("sender-async");
    })();
  }
  const options:any={database,baseURL:"http://localhost:3000",secret:"remaining-background-contract-secret-longer-than-thirty-two",rateLimit:{enabled:false},
    emailAndPassword:{enabled:true,autoSignIn:endpoint!=="signup",password:{hash:async()=>{if(armed)events.push("hash");return "fixture";},verify:async()=>true},
      onExistingUserSignUp:send,customSyntheticUser:(data:any)=>{events.push("synthetic");return {...data.coreFields,...data.additionalFields,id:data.id};}},
    plugins:[organization({sendInvitationEmail:send,organizationHooks:{afterCreateInvitation:async()=>{if(armed)events.push("organization:after");}}})],
    logger:{level:"error",log:(_:unknown,message:unknown,...args:any[])=>{if(typeof message==="string"&&message.startsWith("Failed to run background task")){logs.push({message,error:args[0]?.message??null});events.push(`log:${args[0]?.message}`);}}}};
  if(scheduling!=="default")options.advanced={backgroundTasks:{handler:(task:Promise<unknown>)=>{events.push("handler:received");tasks.push(task);if(scheduling==="handler-throw")throw new Error("handler-sync");}}};
  await(await getMigrations(options)).runMigrations();
  const auth=betterAuth(options);
  const signup=await auth.api.signUpEmail({body:{name:"Owner",email:"owner@example.com",password:"fixture-password"},asResponse:true});
  const cookie=signup.headers.getSetCookie().map(value=>value.split(";")[0]).join("; ");
  let organizationId:string|undefined;
  if(endpoint!=="signup"){
    const org=await auth.api.createOrganization({body:{name:"Company",slug:"company"},headers:{cookie}});organizationId=org!.id;
    if(endpoint==="resend")await auth.api.createInvitation({body:{email:"target@example.com",role:"member",organizationId},headers:{cookie}});
  }
  const rawBody:any=endpoint==="signup"?{name:"Other",email:"owner@example.com",password:"fixture-password",unknown:"drop"}:{email:"TARGET@example.com",role:"member",organizationId,resend:endpoint==="resend",unknown:"drop"};
  const path=endpoint==="signup"?"/sign-up/email":"/organization/invite-member";
  const snapshot=()=>({users:(database.query("select count(*) as count from user").get() as any).count,invitations:(database.query("select count(*) as count from invitation").get() as any).count});
  armed=true;
  const operation=(async()=>{try{
    const headers={cookie,origin:"http://localhost:3000","content-type":"application/json"};
    const response=transport==="http"?await auth.handler(new Request(`http://localhost:3000/api/auth${path}`,{method:"POST",headers,body:JSON.stringify(rawBody)})):
      await (endpoint==="signup"?auth.api.signUpEmail:auth.api.createInvitation)({body:rawBody,headers,asResponse:true} as any);
    return {status:response.status,thrown:null};
  }catch(error:any){return {status:null,thrown:error.message};}finally{done=true;events.push("response");}})();
  await entered.promise;
  const storedBeforeRelease=snapshot();
  const asynchronous=sender==="resolve"||sender==="reject";
  if(!asynchronous||scheduling!=="default")await operation;
  const respondedBeforeRelease=done;
  events.push("gate:release");gate.resolve();
  const outcome=await operation;await finished.promise;
  const taskStates=(await Promise.allSettled(tasks)).map(result=>result.status);
  const storedAfterResponse=snapshot();
  for(const context of contexts)if(context.body.organizationId)context.body={...context.body,organizationId:"<organization>"};
  database.close();
  return {endpoint,transport,scheduling,sender,respondedBeforeRelease,storedBeforeRelease,storedAfterResponse,outcome,events,logs,contexts,taskStates};
}
