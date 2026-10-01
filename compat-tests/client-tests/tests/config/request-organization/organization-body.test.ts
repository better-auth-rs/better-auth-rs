import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

async function post(ctx: any, path: string, body: any, headers: Record<string,string> = {}) {
  return fetch(`${ctx.baseURL}${path}`, {method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body)});
}
async function call(ctx:any, mode:string, path:string, body:any, headers:Record<string,string>={}) {
  return mode === "http" ? post(ctx, `/api/auth/organization/${path}`,body,headers) : post(ctx,"/__test/query-native",{path:`/organization/${path}`,method:"POST",body,headers});
}
async function clear(ctx:any) { await post(ctx,"/__test/body-events",{}); }
async function events(ctx:any) { return (await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events; }
function cookie(response:Response) {
  return Array.from(new Map(response.headers.getSetCookie().map(value=>{const pair=value.split(";",1)[0];const pos=pair.indexOf("=");return [pair.slice(0,pos),pair.slice(pos+1)];})),([key,value])=>`${key}=${value}`).join("; ");
}

for (const mode of ["http","native"]) {
  compatScenario(`${mode}: all Organization body schemas validate before authentication and keep endpoint hooks raw`,async ctx=>{
    const cases:[string,any,string][]=[
      ["create",{name:"",slug:7,logo:4,metadata:null,keepCurrentActiveOrganization:"true"},'[body.name] Too small: expected string to have >=1 characters; [body.slug] Invalid input: expected string, received number; [body.logo] Invalid input: expected string, received number; [body.metadata] Invalid input: expected record, received null; [body.keepCurrentActiveOrganization] Invalid input: expected boolean, received string'],
      ["update",{data:{name:"",slug:null,logo:7,metadata:[]},organizationId:8},'[body.data.name] Too small: expected string to have >=1 characters; [body.data.slug] Invalid input: expected string, received null; [body.data.logo] Invalid input: expected string, received number; [body.data.metadata] Invalid input: expected record, received array; [body.organizationId] Invalid input: expected string, received number'],
      ["delete",{},'[body.organizationId] Invalid input: expected string, received undefined'],
      ["leave",{organizationId:false},'[body.organizationId] Invalid input: expected string, received boolean'],
      ["check-slug",{slug:null},'[body.slug] Invalid input: expected string, received null'],
      ["set-active",{organizationId:5,organizationSlug:null},'[body.organizationId] Invalid input: expected string, received number; [body.organizationSlug] Invalid input: expected string, received null'],
      ["remove-member",{memberIdOrEmail:null,organizationId:[]},'[body.memberIdOrEmail] Invalid input: expected string, received null; [body.organizationId] Invalid input: expected string, received array'],
      ["update-member-role",{role:[7],memberId:3,organizationId:null},'[body.role] Invalid input; [body.memberId] Invalid input: expected string, received number; [body.organizationId] Invalid input: expected string, received null'],
      ["invite-member",{email:7,role:false,organizationId:8,resend:"true",teamId:[9]},'[body.email] Invalid input: expected string, received number; [body.role] Invalid input; [body.organizationId] Invalid input: expected string, received number; [body.resend] Invalid input: expected boolean, received string; [body.teamId] Invalid input'],
      ...["accept-invitation","reject-invitation","cancel-invitation"].map(path=>[path,{invitationId:null},'[body.invitationId] Invalid input: expected string, received null'] as [string,any,string]),
      ["create-team",{name:null,organizationId:7},'[body.name] Invalid input: expected string, received null; [body.organizationId] Invalid input: expected string, received number'],
      ["update-team",{teamId:7,data:{name:false,organizationId:[]}},'[body.teamId] Invalid input: expected string, received number; [body.data.name] Invalid input: expected string, received boolean; [body.data.organizationId] Invalid input: expected string, received array'],
      ["remove-team",{teamId:false,organizationId:7},'[body.teamId] Invalid input: expected string, received boolean; [body.organizationId] Invalid input: expected string, received number'],
      ["set-active-team",{teamId:7},'[body.teamId] Invalid input: expected string, received number'],
      ...["add-team-member","remove-team-member"].map(path=>[path,{teamId:7,userId:[7],organizationId:false},'[body.teamId] Invalid input: expected string, received number; [body.organizationId] Invalid input: expected string, received boolean'] as [string,any,string]),
      ["create-role",{organizationId:7,role:null,permission:{project:[7]},additionalFields:null},'[body.organizationId] Invalid input: expected string, received number; [body.role] Invalid input: expected string, received null; [body.permission.project.0] Invalid input: expected string, received number; [body.additionalFields] Invalid input: expected object, received null'],
      ["update-role",{organizationId:7,data:{permission:{project:7},roleName:null},roleName:"",roleId:""},'[body.organizationId] Invalid input: expected string, received number; [body.data.permission.project] Invalid input: expected array, received number; [body.data.roleName] Invalid input: expected string, received null; [body] Invalid input'],
      ["delete-role",{organizationId:7,roleName:"",roleId:""},'[body.organizationId] Invalid input: expected string, received number; [body] Invalid input'],
      ["has-permission",{organizationId:7,permission:{},permissions:{}},'[body.organizationId] Invalid input: expected string, received number; [body] Invalid input: more than one option matched'],
    ];
    const observed=[];
    for (const [path,body,message] of cases) {
      await clear(ctx);
      const response=await call(ctx,mode,path,body);
      const result=await response.json();
      expect({path,status:response.status,result}).toEqual({path,status:400,result:{code:"VALIDATION_ERROR",message}});
      const trace=await events(ctx);
      expect(trace.map((event:any)=>event.phase)).toEqual(["before","plugin.before","after"]);
      for(const event of trace){expect(event.body).toEqual(body);expect(event.request).toBe(mode==="http");expect(event.requestBody).toBe(mode==="http"?JSON.stringify(body):null);}
      observed.push({path,result,trace});
    }
    return observed;
  });

  compatScenario(`${mode}: role selector intersections preserve dirty union branches and strip the unselected selector`,async ctx=>{
    const observed=[];
    for(const path of ["delete-role","update-role"]){
      for(const [selectors,message] of [
        [{roleName:""},'[body.roleName] Too small: expected string to have >=1 characters'],
        [{roleId:""},'[body.roleId] Too small: expected string to have >=1 characters'],
        [{roleName:"",roleId:""},'[body] Invalid input'],
        [{roleName:7,roleId:""},'[body.roleId] Too small: expected string to have >=1 characters'],
        [{roleName:"",roleId:7},'[body.roleName] Too small: expected string to have >=1 characters'],
      ] as const){
        const body={...selectors,...(path==="update-role"?{data:{}}:{})};
        const response=await call(ctx,mode,path,body);
        const result=await response.json();
        expect(response.status).toBe(400);expect(result).toEqual({code:"VALIDATION_ERROR",message});observed.push({path,result});
      }
    }
    const signup=await post(ctx,"/api/auth/sign-up/email",{name:"Organization schemas",email:`organization-${mode}@query.example`,password:"fixture-password"});
    expect(signup.status).toBe(200);const headers={cookie:cookie(signup)};
    await clear(ctx);
    const createBody={name:"Schema organization",slug:`schema-${mode}`,logo:null,unknown:"raw"};
    const created=await call(ctx,mode,"create",createBody,headers);expect(created.status).toBe(200);
    const organization=await created.json();
    const trace=await events(ctx);expect(trace.map((event:any)=>event.phase)).toEqual(["before","plugin.before","organization.create","team.create","after"]);
    for(const event of trace){expect(event.body).toEqual(event.phase.endsWith(".create")?{name:createBody.name,slug:createBody.slug,logo:null}:createBody);}
    const role=await call(ctx,mode,"create-role",{organizationId:organization.id,role:"custom",permission:{organization:["update"]},unknown:"raw"},headers);
    expect(role.status).toBe(200);const roleBody=await role.json();
    const roleId=roleBody.roleData.id;
    const updated=await call(ctx,mode,"update-role",{organizationId:organization.id,roleName:"",roleId,data:{roleName:"renamed",unknown:"drop"},unknown:"raw"},headers);expect(updated.status).toBe(200);
    const deleted=await call(ctx,mode,"delete-role",{organizationId:organization.id,roleName:"renamed",roleId:"missing",unknown:"raw"},headers);expect(deleted.status).toBe(200);expect(await deleted.json()).toEqual({success:true});
    const alias=await call(ctx,mode,"has-permission",{organizationId:organization.id,permission:{organization:["update"]}},headers);expect(alias.status).toBe(200);expect(await alias.json()).toEqual({error:null,success:false});
    return {observed,trace};
  });
}
