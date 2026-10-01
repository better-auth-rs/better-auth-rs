import {getCurrentAuthEndpointContext} from "@better-auth/core/context";
import {apiKey} from "@better-auth/api-key";
import {passkey} from "@better-auth/passkey";
import {createAccessControl} from "better-auth/plugins/access";
import {defaultStatements} from "better-auth/plugins/organization/access";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { admin, organization, username, multiSession, oneTimeToken, magicLink, oneTap, deviceAuthorization, siwe } from "better-auth/plugins";
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
  let deviceIndex=0;
  const bodyEvents: unknown[]=[];
  const emailEvents:unknown[]=[];
  const requestBodies=new WeakMap<Request,string>();
  const bodyCapture=async(phase:string,ctx:any)=>{
    if(!ctx?.path?.startsWith("/organization/")&&!["/sign-in/email","/sign-up/email","/request-password-reset","/change-password","/verify-password","/sign-out","/revoke-session","/unlink-account","/change-email","/delete-user","/get-access-token","/refresh-token","/sign-in/username","/is-username-available","/one-time-token/verify","/multi-session/set-active","/multi-session/revoke","/sign-in/magic-link","/one-tap/callback","/passkey/verify-registration","/passkey/verify-authentication","/passkey/update-passkey","/passkey/delete-passkey","/device/code","/device/token","/device/approve","/device/deny","/siwe/nonce","/siwe/get-nonce","/siwe/verify","/send-verification-email"].includes(ctx?.path))return;
    bodyEvents.push({phase,body:snapshot(ctx.body),request:!!ctx.request,requestBody:ctx.request?(requestBodies.get(ctx.request)??await ctx.request.clone().text()):null,errorCode:ctx.context.returned?.body?.code??null});
  };
  const record=(phase:string,ctx:any)=>events.push({phase,path:ctx.path,query:snapshot(ctx.query),url:requestURL(ctx.request)});
  const endpoint=(path:string,validated:boolean)=>createAuthEndpoint(path,{method:"GET",...(validated?{query:getSessionQuerySchema}:{})},async ctx=>{
    record("endpoint",ctx);
    return ctx.json({query:snapshot(ctx.query),url:requestURL(ctx.request)});
  });
  const emailCapture=async(kind:string,data:any,request?:Request)=>{
    const ctx=getCurrentAuthEndpointContext();
    await bodyCapture(kind==="confirmation"?"email.confirmation":"email.sender",ctx);
    if(ctx?.path!=="/change-email")return;
    const claims=JSON.parse(Buffer.from(data.token.split(".")[1],"base64url").toString());
    emailEvents.push({kind,user:data.user,newEmail:data.newEmail??null,claims:{email:claims.email,updateTo:claims.updateTo??null,requestType:claims.requestType??null,expiresIn:claims.exp-claims.iat},callback:new URL(data.url).searchParams.get("callbackURL"),request:!!request,cookieIssued:!!ctx.context.newSession});
    if(ctx.headers?.has("x-email-fail"))throw new Error("fixture sender failure");
  };
  const database=profile.endsWith("-sqlite")||profile.startsWith("request-change-email")?new Database(":memory:"):undefined;
  const options={
    baseURL,secret:"query-fixture-secret-with-at-least-32-characters",database,
    logger:{disabled:true},rateLimit:{enabled:false},advanced:{disableOriginCheck:false},
    ...((profile.startsWith("request-plugin-")||profile.startsWith("request-change-email"))?{emailVerification:{...(profile==="request-change-email-no-sender"?{}:{sendVerificationEmail:async(data:any,request?:Request)=>emailCapture("verification",data,request)}),...(profile==="request-change-email-no-confirmation"?{expiresIn:90}:{})}}:{}),
    emailAndPassword:{enabled:true,sendResetPassword:async()=>{await bodyCapture("sender",getCurrentAuthEndpointContext());},password:{hash:async()=>{await bodyCapture("hash",getCurrentAuthEndpointContext());return "fixture-hash";},verify:async({password}:any)=>{await bodyCapture("verify",getCurrentAuthEndpointContext());return password==="fixture-password";}}},
    user:{deleteUser:{enabled:true},changeEmail:{enabled:profile!=="request-change-email-disabled",updateEmailWithoutVerification:true,...(profile.startsWith("request-change-email")&&profile!=="request-change-email-no-confirmation"?{sendChangeEmailConfirmation:async(data:any,request?:Request)=>emailCapture("confirmation",data,request)}:{})}},
    session:{cookieCache:{enabled:true,maxAge:3600}},
    databaseHooks:{user:{update:{before:async(_:any,ctx:any)=>{await bodyCapture("user.update.before",ctx);if(ctx?.path==="/change-email"&&ctx.headers?.has("x-user-update-cancel"))return false;},after:async(_:any,ctx:any)=>{await bodyCapture("user.update.after",ctx);}},create:{before:async(_:any,ctx:any)=>{await bodyCapture("user.before",ctx);},after:async(_:any,ctx:any)=>{await bodyCapture("user.after",ctx);}}},session:{delete:{before:async(_:any,ctx:any)=>{await bodyCapture("session.delete.before",ctx);},after:async(_:any,ctx:any)=>{await bodyCapture("session.delete.after",ctx);}},create:{before:async(_:any,ctx:any)=>{await bodyCapture("session.before",ctx);},after:async(_:any,ctx:any)=>{await bodyCapture("session.after",ctx);}}}},
    hooks:{before:createAuthMiddleware(async ctx=>{await bodyCapture("before",ctx);if(ctx.path==="/sign-in/email"&&ctx.headers?.get("x-body-mode")==="replace")return {context:{body:{password:"fixture-password",callbackURL:"/replaced",added:"replacement"}}};})},
    plugins:[...(profile.startsWith("request-security-")?[
      magicLink({sendMagicLink:async(message:any)=>{await bodyCapture("magic.sender",getCurrentAuthEndpointContext());emailEvents.push({kind:"magic",...message});}}),
      oneTap({clientId:"request-security-client"}),
      deviceAuthorization({generateDeviceCode:async()=>`request-device-${++deviceIndex}`,generateUserCode:async()=>`REQ2345${deviceIndex}`,onDeviceAuthRequest:async()=>{await bodyCapture("device.sender",getCurrentAuthEndpointContext());}}),
      siwe({domain:"localhost",anonymous:false,getNonce:async()=>{await bodyCapture("siwe.nonce",getCurrentAuthEndpointContext());return "REQUESTNONCE2345";},verifyMessage:async()=>false}),
    ]:[]),...(profile.startsWith("request-plugin-")?[username(),multiSession(),oneTimeToken()]:[]),admin({defaultRole:"admin"}),organization({organizationHooks:{beforeCreateOrganization:async()=>{await bodyCapture("organization.create",getCurrentAuthEndpointContext());},beforeUpdateOrganization:async()=>{await bodyCapture("organization.update",getCurrentAuthEndpointContext());},beforeCreateTeam:async()=>{await bodyCapture("team.create",getCurrentAuthEndpointContext());},beforeUpdateTeam:async()=>{await bodyCapture("team.update",getCurrentAuthEndpointContext());},beforeCreateInvitation:async()=>{await bodyCapture("invitation.create",getCurrentAuthEndpointContext());}},ac:createAccessControl(defaultStatements),teams:{enabled:true},dynamicAccessControl:{enabled:true}}),apiKey(),passkey(),{id:"request-query",endpoints:{
      rawQuery:endpoint("/query/raw",false),validatedQuery:endpoint("/query/validated",true),
    },hooks:{
      before:[{matcher:()=>true,handler:createAuthMiddleware(async ctx=>{record("before",ctx);await bodyCapture("plugin.before",ctx);})}],
      after:[{matcher:()=>true,handler:createAuthMiddleware(async ctx=>{record("after",ctx);await bodyCapture("after",ctx);})}],
    }}],
  };
  if(database) await(await getMigrations(options as any)).runMigrations();
  const auth=betterAuth(options as any);
  const nativeMethods:Record<string,string>={"/sign-in/magic-link":"signInMagicLink","/one-tap/callback":"oneTapCallback","/passkey/verify-registration":"verifyPasskeyRegistration","/passkey/verify-authentication":"verifyPasskeyAuthentication","/passkey/update-passkey":"updatePasskey","/passkey/delete-passkey":"deletePasskey","/device/code":"deviceCode","/device/token":"deviceToken","/device/approve":"deviceApprove","/device/deny":"deviceDeny","/siwe/nonce":"getSiweNonce","/siwe/get-nonce":"getNonce","/siwe/verify":"verifySiweMessage","/organization/create":"createOrganization","/organization/update":"updateOrganization","/organization/delete":"deleteOrganization","/organization/set-active":"setActiveOrganization","/organization/check-slug":"checkOrganizationSlug","/organization/leave":"leaveOrganization","/organization/remove-member":"removeMember","/organization/update-member-role":"updateMemberRole","/organization/invite-member":"createInvitation","/organization/accept-invitation":"acceptInvitation","/organization/reject-invitation":"rejectInvitation","/organization/cancel-invitation":"cancelInvitation","/organization/create-team":"createTeam","/organization/update-team":"updateTeam","/organization/remove-team":"removeTeam","/organization/set-active-team":"setActiveTeam","/organization/add-team-member":"addTeamMember","/organization/remove-team-member":"removeTeamMember","/organization/create-role":"createOrgRole","/organization/update-role":"updateOrgRole","/organization/delete-role":"deleteOrgRole","/organization/has-permission":"hasPermission","/sign-in/username":"signInUsername","/is-username-available":"isUsernameAvailable","/one-time-token/verify":"verifyOneTimeToken","/multi-session/set-active":"setActiveSession","/multi-session/revoke":"revokeDeviceSession","/send-verification-email":"sendVerificationEmail","/one-time-token/generate":"generateOneTimeToken","/revoke-session":"revokeSession","/unlink-account":"unlinkAccount","/change-email":"changeEmail","/delete-user":"deleteUser","/get-access-token":"getAccessToken","/refresh-token":"refreshToken","/sign-up/email":"signUpEmail","/request-password-reset":"requestPasswordReset","/change-password":"changePassword","/verify-password":"verifyPassword","/sign-out":"signOut","/sign-in/email":"signInEmail","/callback/google":"callbackOAuth","/query/raw":"rawQuery","/query/validated":"validatedQuery","/get-session":"getSession","/admin/list-users":"listUsers","/admin/get-user":"getUser","/organization/list-members":"listMembers",
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
    if(path==="/__test/email-events"){if(request.method==="POST")emailEvents.length=0;return Response.json({events:emailEvents});}
    if(path==="/__test/device-record"){const input=await request.json();return Response.json(await(await auth.$context).adapter.findOne({model:"deviceCode",where:[{field:"deviceCode",value:input.deviceCode}]}));}
    if(path==="/__test/query-user-verified"){const {id,emailVerified}=await request.json();await(await auth.$context).internalAdapter.updateUser(id,{emailVerified});return Response.json({success:true});}
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
