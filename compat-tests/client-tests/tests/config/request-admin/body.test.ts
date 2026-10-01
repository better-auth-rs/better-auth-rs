import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}) {return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body)});}
async function call(ctx:any,mode:string,path:string,body:any,headers:Record<string,string>={}) {return mode==="http"?post(ctx,`/api/auth/admin/${path}`,body,headers):post(ctx,"/__test/query-native",{path:`/admin/${path}`,method:"POST",body,headers});}
async function clear(ctx:any){await post(ctx,"/__test/body-events",{});}
async function events(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;}
function cookie(response:Response){return Array.from(new Map(response.headers.getSetCookie().map(v=>{const pair=v.split(";",1)[0],p=pair.indexOf("=");return[pair.slice(0,p),pair.slice(p+1)];})),([k,v])=>`${k}=${v}`).join("; ");}
async function signup(ctx:any,email:string){const r=await post(ctx,"/api/auth/sign-up/email",{name:"Admin schemas",email,password:"fixture-password"});expect(r.status).toBe(200);return {data:await r.json(),headers:{cookie:cookie(r)}};}
for(const mode of ["http","native"]){
 compatScenario(`${mode}: Admin body schemas precede authentication and aggregate errors in schema order`,async ctx=>{
  const cases:[string,any,string][]=[
   ["set-role",{role:"user"},"[body.userId] Invalid input: expected nonoptional, received undefined"],
   ["set-role",{userId:{},role:[4]},"[body.role] Invalid input"],
   ["create-user",{email:4,password:null,name:[],role:false,data:[]},"[body.email] Invalid input: expected string, received number; [body.password] Invalid input: expected string, received null; [body.name] Invalid input: expected string, received array; [body.role] Invalid input; [body.data] Invalid input: expected record, received array"],
   ["update-user",{userId:false,data:null},"[body.data] Invalid input: expected record, received null"],
   ["ban-user",{userId:[],banReason:null,banExpiresIn:"5"},"[body.banReason] Invalid input: expected string, received null; [body.banExpiresIn] Invalid input: expected number, received string"],
   ["revoke-user-session",{sessionToken:4},"[body.sessionToken] Invalid input: expected string, received number"],
   ["set-user-password",{newPassword:"",userId:[]},"[body.newPassword] newPassword cannot be empty; [body.userId] userId cannot be empty"],
   ["set-user-password",{newPassword:4,userId:""},"[body.newPassword] Invalid input: expected string, received number; [body.userId] userId cannot be empty"],
   ["has-permission",{role:4,permission:{},permissions:{}},"[body.role] Invalid input: expected string, received number; [body] Invalid input: more than one option matched"],
   ["has-permission",{permissions:{user:[4]}},"[body] Invalid input"],
   ...["list-user-sessions","unban-user","impersonate-user","revoke-user-sessions","remove-user"].map(path=>[path,[],"[body] Invalid input: expected object, received array"] as [string,any,string]),
  ];
  const observed=[];
  for(const [path,body,message]of cases){await clear(ctx);const r=await call(ctx,mode,path,body);const result=await r.json();expect({path,status:r.status,result}).toEqual({path,status:400,result:{code:"VALIDATION_ERROR",message}});const trace=await events(ctx);expect(trace.map((e:any)=>e.phase)).toEqual(["before","plugin.before","after"]);for(const e of trace){expect(e.body).toEqual(body);expect(e.request).toBe(mode==="http");}observed.push({path,result,trace});}
  for(const path of ["set-role","list-user-sessions","unban-user","impersonate-user","revoke-user-sessions","remove-user","ban-user"]){for(const userId of [null,42,false,[],[7],{}]){const r=await call(ctx,mode,path,{userId,...(path==="set-role"?{role:"user"}:{})});expect({path,userId,status:r.status}).toEqual({path,userId,status:401});expect(await r.text()).toBe("");}}
  return observed;
 });
 compatScenario(`${mode}: Admin creates credentials and persists projected mutations with session revocation`,async ctx=>{
  const owner=await signup(ctx,`owner-${mode}@admin-schema.example`);await clear(ctx);
  const invalidEmail=await call(ctx,mode,"create-user",{name:"Bad email",email:"user@localhost"},owner.headers);expect(invalidEmail.status).toBe(400);expect(await invalidEmail.json()).toEqual({code:"INVALID_EMAIL",message:"Invalid email"});
  await clear(ctx);
  const body={name:"Managed user",email:`target-${mode}@admin-schema.example`,role:"user",data:{image:null},unknown:"raw"};
  const create=await call(ctx,mode,"create-user",body,owner.headers);expect(create.status).toBe(200);const {user}=await create.json();expect(user.name).toBe(body.name);expect(user.role).toBe("user");expect(user.image).toBeNull();
  const trace=await events(ctx);for(const e of trace){const raw=["before","plugin.before","after"].includes(e.phase);expect(e.body).toEqual(raw?body:{name:body.name,email:body.email,role:"user",data:{image:null}});}
  await clear(ctx);
  const setPassword=await call(ctx,mode,"set-user-password",{userId:user.id,newPassword:"fixture-password",unknown:true},owner.headers);expect(setPassword.status).toBe(200);expect(await setPassword.json()).toEqual({status:true});
  const signIn=await post(ctx,"/api/auth/sign-in/email",{email:body.email,password:"fixture-password"});expect(signIn.status).toBe(200);const targetCookie=cookie(signIn);
  const actorWins=await call(ctx,mode,"has-permission",{role:"admin",userId:owner.data.user.id,permissions:{user:["delete"]}},{cookie:targetCookie});expect(actorWins.status).toBe(200);expect(await actorWins.json()).toEqual({error:null,success:false});
  const list=await call(ctx,mode,"list-user-sessions",{userId:user.id,unknown:7},owner.headers);expect(list.status).toBe(200);const sessions=await list.json();expect(sessions.sessions.length).toBe(1);
  const impersonate=await call(ctx,mode,"impersonate-user",{userId:[user.id],unknown:true},owner.headers);expect(impersonate.status).toBe(200);expect((await impersonate.json()).user.id).toBe(user.id);
  const stop=await call(ctx,mode,"stop-impersonating",{ignored:true},{cookie:cookie(impersonate)});expect(stop.status).toBe(200);expect((await stop.json()).user.id).toBe(owner.data.user.id);
  const noop=await call(ctx,mode,"revoke-user-session",{sessionToken:"",unknown:true},owner.headers);expect(noop.status).toBe(200);expect(await noop.json()).toEqual({success:true});
  const before=Date.now();const ban=await call(ctx,mode,"ban-user",{userId:user.id,banReason:"",banExpiresIn:0.5},owner.headers);expect(ban.status).toBe(200);const banned=await ban.json();expect(banned.user.banned).toBe(true);expect(banned.user.banReason).toBe("No reason");expect(Date.parse(banned.user.banExpires)-before).toBeGreaterThanOrEqual(500);expect(Date.parse(banned.user.banExpires)-Date.now()).toBeLessThanOrEqual(500);
  const denied=await fetch(`${ctx.baseURL}/api/auth/get-session?disableCookieCache=true`,{headers:{cookie:targetCookie}});expect(await denied.json()).toBeNull();
  const unban=await call(ctx,mode,"unban-user",{userId:user.id},owner.headers);expect(unban.status).toBe(200);const unbanned=await unban.json();expect(unbanned.user.banned).toBe(false);expect(unbanned.user.banReason).toBeNull();expect(unbanned.user.banExpires).toBeNull();
  const role=await call(ctx,mode,"set-role",{userId:[user.id],role:["admin","user"],unknown:"strip"},owner.headers);expect(role.status).toBe(200);expect((await role.json()).user.role).toBe("admin,user");
  const update=await call(ctx,mode,"update-user",{userId:user.id,data:{name:"Changed"},unknown:7},owner.headers);expect(update.status).toBe(200);const updated=await update.json();expect(updated.name).toBe("Changed");
  const emptyId=await fetch(`${ctx.baseURL}/api/auth/admin/get-user?id=`,{headers:owner.headers});expect(emptyId.status).toBe(404);expect(await emptyId.json()).toEqual({code:"USER_NOT_FOUND",message:"User not found"});
  const missing=await call(ctx,mode,"set-user-password",{userId:"absent",newPassword:"fixture-password"},owner.headers);expect(missing.status).toBe(404);expect(await missing.json()).toEqual({code:"USER_NOT_FOUND",message:"User not found"});
  const forbidden=await call(ctx,mode,"remove-user",{userId:owner.data.user.id},owner.headers);expect(forbidden.status).toBe(400);expect((await forbidden.json()).code).toBe("YOU_CANNOT_REMOVE_YOURSELF");
  const revoked=await call(ctx,mode,"revoke-user-sessions",{userId:[user.id]},owner.headers);expect(revoked.status).toBe(200);expect(await revoked.json()).toEqual({success:true});
  const removed=await call(ctx,mode,"remove-user",{userId:user.id},owner.headers);expect(removed.status).toBe(200);expect(await removed.json()).toEqual({success:true});
  return {created:user,trace,updated,unbanned,revoked:true};
 });
}
compatScenario("native Admin trusted calls retain omitted headers, explicit empty headers, and permission XOR semantics",async ctx=>{
 const out=[];
 const native=(path:string,body:any,extra:any={})=>post(ctx,"/__test/query-native",{path:`/admin/${path}`,method:"POST",body,...extra});
 for(const [extra,status] of [[{},200],[{headers:{}},401],[{request:`${ctx.baseURL}/native-admin`},401]] as const){const r=await native("create-user",{email:`native-${status}-${Object.hasOwn(extra,"request")}@admin-schema.example`,name:"Trusted"},extra);expect(r.status).toBe(status);out.push({status,body:status===200?(await r.json()).user:await r.text()});}
 for(const path of ["set-role","stop-impersonating"]){for(const extra of [{},{request:`${ctx.baseURL}/native-request`}]){const r=await native(path,{role:"user",userId:"missing"},extra);expect(r.status).toBe(400);expect(await r.json()).toEqual({code:"VALIDATION_ERROR",message:"Headers is required"});}}
 const stopEmpty=await native("stop-impersonating",{}, {headers:{}});expect(stopEmpty.status).toBe(401);expect(await stopEmpty.text()).toBe("");
 const cases:[any,any,number,any][]=[
  [{role:"admin",permissions:{user:["create"]}},{},200,{error:null,success:true}],
  [{role:"user",permissions:{user:["create"]}},{},200,{error:null,success:false}],
  [{userId:0,role:"admin",permissions:{}},{},200,{error:null,success:false}],
  [{role:"admin",permissions:{}},{headers:{}},401,null],
  [{role:"admin",permission:{}},{},400,{message:"invalid permission check. no permission(s) were passed."}],
  [{permissions:{}},{},400,{message:"user id or role is required"}],
  [{userId:"missing",permissions:{}},{},400,{message:"user not found"}],
 ];
 for(const [body,extra,status,result]of cases){const r=await native("has-permission",body,extra);expect(r.status).toBe(status);const raw=await r.text(),value=raw?JSON.parse(raw):null;expect(value).toEqual(result);out.push({body,status,result:value});}
 return out;
});
