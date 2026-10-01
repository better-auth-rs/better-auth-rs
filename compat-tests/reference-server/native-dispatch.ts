import {kAPIErrorHeaderSymbol} from "better-call";
import {betterAuth} from "better-auth";
import {APIError,createAuthMiddleware} from "better-auth/api";
import {emailOTP,jwt,twoFactor} from "better-auth/plugins";
import {getCurrentAuthEndpointContext} from "@better-auth/core/context";

export function createNativeDispatchFixture(baseURL:string){
 let mode="normal",operation="",events:any[]=[];
 const absent=(v:any)=>v===undefined?{$undefined:true}:structuredClone(v);
 const output=(value:string)=>operation==="createVerificationOTP"?value:operation==="signJWT"?{token:value}:operation==="verifyJWT"?{payload:{sub:value}}:operation==="getVerificationOTP"?{otp:value}:operation==="viewBackupCodes"?{status:true,backupCodes:[value]}:{code:value};
 function record(phase:string,ctx:any){events.push({phase,path:ctx.path,ambient:absent(getCurrentAuthEndpointContext()?.path),body:absent(ctx.body),query:absent(ctx.query),request:ctx.request?new URL(ctx.request.url).pathname:null,header:ctx.headers?.get("x-literal")??null});}
 const auth=betterAuth({baseURL,secret:"native-dispatch-fixture-secret-more-than-32",logger:{disabled:true},rateLimit:{enabled:false},
  hooks:{before:createAuthMiddleware(async ctx=>{record("before",ctx);if(mode==="stop"){if(operation==="createVerificationOTP")throw new APIError("BAD_REQUEST",{code:"STOPPED",message:"stopped"});return ctx.json(output("stopped"));}if(mode==="options")return{context:{body:{overrideOptions:{jwt:{issuer:"changed-issuer",audience:["one","two"],expirationTime:"2 minutes"}}}}};if(mode==="patch"||mode==="invalid"){
   const key=operation==="generateTOTP"?"secret":operation==="signJWT"?"payload":operation==="verifyJWT"?"token":"email";
   const value=mode==="invalid"?7:key==="payload"?{sub:"changed"}:key==="email"?"PATCHED@example.test":"patched-secret";
   return{context:{[operation==="getVerificationOTP"?"query":"body"]:{[key]:value,unknown:true}}};
  }}),after:createAuthMiddleware(async ctx=>{record("after",ctx);if(mode==="after-error"){ctx.setHeader("x-native-error","retained");throw new APIError("BAD_REQUEST",{code:"AFTER_REJECTION",message:"after rejection"});}if(mode==="replace")return ctx.json(output("replaced"));})},
  plugins:[emailOTP({generateOTP:(_data,ctx)=>{record("generator",ctx);if(mode==="ordinary")throw new Error("generator failed");return"123456";}}),jwt(),twoFactor(),{id:"native-trace",hooks:{before:[{matcher:()=>true,handler:createAuthMiddleware(async ctx=>{record("plugin.before",ctx)})}],after:[{matcher:()=>true,handler:createAuthMiddleware(async ctx=>{record("plugin.after",ctx)})}]}}]});
 return {handle:async(request:Request)=>{
  const path=new URL(request.url).pathname;
  if(path==="/health"||path==="/__health")return Response.json({status:"ok"});
  if(path==="/__test/reset-state")return Response.json({success:true});
  if(path!=="/__test/native-dispatch")return auth.handler(request);
  const input=await request.json();mode=input.mode??"normal";operation=input.operation;events=[];
  const options:any={asResponse:false};if(input.body!==undefined)options.body=input.body;if(input.query!==undefined)options.query=input.query;
  if(input.headers!==undefined)options.headers=new Headers(input.headers);if(input.request)options.request=new Request(baseURL+"/original?literal=true");
  try {const result=await(auth.api as any)[operation](options);return Response.json({result,events});}
  catch(error:any){return Response.json({error:error.name==="APIError"?{status:typeof error.status==="number"?error.status:error.statusCode,body:error.body}:{ordinary:true,message:error.message},events,errorHeaders:error[kAPIErrorHeaderSymbol]?.get("x-native-error")??null});}
 }};
}
