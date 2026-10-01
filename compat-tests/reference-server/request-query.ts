import {getCurrentAuthEndpointContext} from "@better-auth/core/context";
import {apiKey} from "@better-auth/api-key";
import {passkey} from "@better-auth/passkey";
import {createAccessControl} from "better-auth/plugins/access";
import {defaultStatements} from "better-auth/plugins/organization/access";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { z } from "zod";

const getSessionQuerySchema=z.object({disableCookieCache:z.coerce.boolean().optional(),disableRefresh:z.coerce.boolean().optional()}).optional();

const snapshot = (value: unknown) => value === undefined ? {$undefined:true} : structuredClone(value);
function requestURL(request?: Request) {
  if (!request) return null;
  const url=new URL(request.url);
  return `${url.pathname}${url.search}`;
}

export async function createRequestQueryFixture(profile: string, baseURL: string) {
  const events: unknown[]=[];
  const bodyEvents: unknown[]=[];
  const requestBodies=new WeakMap<Request,string>();
  const bodyCapture=async(phase:string,ctx:any)=>{
    if(!["/sign-in/email","/sign-up/email","/request-password-reset","/change-password","/verify-password","/sign-out","/revoke-session","/unlink-account","/change-email","/delete-user","/get-access-token","/refresh-token"].includes(ctx?.path))return;
    bodyEvents.push({phase,body:structuredClone(ctx.body),request:!!ctx.request,requestBody:ctx.request?(requestBodies.get(ctx.request)??await ctx.request.clone().text()):null,errorCode:ctx.context.returned?.body?.code??null});
  };
  const record=(phase:string,ctx:any)=>events.push({phase,path:ctx.path,query:snapshot(ctx.query),url:requestURL(ctx.request)});
  const endpoint=(path:string,validated:boolean)=>createAuthEndpoint(path,{method:"GET",...(validated?{query:getSessionQuerySchema}:{})},async ctx=>{
    record("endpoint",ctx);
    return ctx.json({query:snapshot(ctx.query),url:requestURL(ctx.request)});
  });
  const database=profile==="request-query-sqlite"?new Database(":memory:"):undefined;
  const options={
    baseURL,secret:"query-fixture-secret-with-at-least-32-characters",database,
    logger:{disabled:true},rateLimit:{enabled:false},
    emailAndPassword:{enabled:true,sendResetPassword:async()=>{await bodyCapture("sender",getCurrentAuthEndpointContext());},password:{hash:async()=>{await bodyCapture("hash",getCurrentAuthEndpointContext());return "fixture-hash";},verify:async({password}:any)=>{await bodyCapture("verify",getCurrentAuthEndpointContext());return password==="fixture-password";}}},
    user:{deleteUser:{enabled:true},changeEmail:{enabled:true,updateEmailWithoutVerification:true}},
    session:{cookieCache:{enabled:true,maxAge:3600}},
    databaseHooks:{user:{update:{before:async(_:any,ctx:any)=>{await bodyCapture("user.update.before",ctx);},after:async(_:any,ctx:any)=>{await bodyCapture("user.update.after",ctx);}},create:{before:async(_:any,ctx:any)=>{await bodyCapture("user.before",ctx);},after:async(_:any,ctx:any)=>{await bodyCapture("user.after",ctx);}}},session:{delete:{before:async(_:any,ctx:any)=>{await bodyCapture("session.delete.before",ctx);},after:async(_:any,ctx:any)=>{await bodyCapture("session.delete.after",ctx);}},create:{before:async(_:any,ctx:any)=>{await bodyCapture("session.before",ctx);},after:async(_:any,ctx:any)=>{await bodyCapture("session.after",ctx);}}}},
    hooks:{before:createAuthMiddleware(async ctx=>{await bodyCapture("before",ctx);if(ctx.path==="/sign-in/email"&&ctx.headers?.get("x-body-mode")==="replace")return {context:{body:{password:"fixture-password",callbackURL:"/replaced",added:"replacement"}}};})},
    plugins:[admin({defaultRole:"admin"}),organization({ac:createAccessControl(defaultStatements),teams:{enabled:true},dynamicAccessControl:{enabled:true}}),apiKey(),passkey(),{id:"request-query",endpoints:{
      rawQuery:endpoint("/query/raw",false),validatedQuery:endpoint("/query/validated",true),
    },hooks:{
      before:[{matcher:()=>true,handler:createAuthMiddleware(async ctx=>{record("before",ctx);await bodyCapture("plugin.before",ctx);})}],
      after:[{matcher:()=>true,handler:createAuthMiddleware(async ctx=>{record("after",ctx);await bodyCapture("after",ctx);})}],
    }}],
  };
  if(database) await(await getMigrations(options as any)).runMigrations();
  const auth=betterAuth(options as any);
  const nativeMethods:Record<string,string>={"/revoke-session":"revokeSession","/unlink-account":"unlinkAccount","/change-email":"changeEmail","/delete-user":"deleteUser","/get-access-token":"getAccessToken","/refresh-token":"refreshToken","/sign-up/email":"signUpEmail","/request-password-reset":"requestPasswordReset","/change-password":"changePassword","/verify-password":"verifyPassword","/sign-out":"signOut","/sign-in/email":"signInEmail","/callback/google":"callbackOAuth","/query/raw":"rawQuery","/query/validated":"validatedQuery","/get-session":"getSession","/admin/list-users":"listUsers","/admin/get-user":"getUser","/organization/list-members":"listMembers",
    "/passkey/generate-register-options":"generatePasskeyRegistrationOptions",
    "/api-key/get":"getApiKey","/api-key/list":"listApiKeys",
    "/reset-password":"resetPassword","/reset-password/missing":"requestPasswordResetCallback",
    "/delete-user/callback":"deleteUserCallback","/account-info":"accountInfo",
    "/organization/get-organization":"getOrganization","/organization/get-full-organization":"getFullOrganization",
    "/organization/get-invitation":"getInvitation","/organization/list-invitations":"listInvitations",
    "/organization/list-user-invitations":"listUserInvitations","/organization/list-teams":"listOrganizationTeams",
    "/organization/list-user-teams":"listUserTeams","/organization/list-team-members":"listTeamMembers",
    "/organization/get-active-member-role":"getActiveMemberRole","/organization/get-role":"getOrgRole","/organization/list-roles":"listOrgRoles"};
  return {auth,async handle(request:Request):Promise<Response>{
    const path=new URL(request.url).pathname;
    if(path==="/health"||path==="/__health")return Response.json({status:"ok"});
    if(path==="/__test/reset-state"){events.length=0;return Response.json({success:true});}
    if(path==="/__test/body-events"){if(request.method==="POST")bodyEvents.length=0;return Response.json({events:bodyEvents});}
    if(path==="/__test/query-events"){if(request.method==="POST")events.length=0;return Response.json({events});}
    if(path==="/__test/query-native"){
      const input=await request.json();
      const method=nativeMethods[input.path];
      if(!method)throw new Error(`Unknown query endpoint ${input.path}`);
      const response=await(auth.api as any)[method]({
        ...(Object.hasOwn(input,"query")?{query:input.query}:{}),
        ...(Object.hasOwn(input,"body")?{body:input.body}:{}),
        ...(input.method?{method:input.method}:{}),
        ...(input.path==="/reset-password/missing"?{params:{token:"missing"}}:{}),
        ...(input.path==="/callback/google"?{params:{id:"google"}}:{}),
        ...(Object.hasOwn(input,"headers")?{headers:input.headers}:{}),
        ...(input.request?{request:new Request(input.request,input.requestBody?{method:"POST",body:input.requestBody,headers:{"content-type":"application/json"}}:undefined)}:{}),asResponse:true,
      });
      return response;
    }
    if(path==="/__test/query-member")return Response.json(await auth.api.addMember({body:await request.json()}));
    if(path==="/__test/query-user"){
      const {id,name}=await request.json();
      await(await auth.$context).internalAdapter.updateUser(id,{name});
      return Response.json({success:true});
    }
    requestBodies.set(request,await request.clone().text());
    return auth.handler(request);
  }};
}
