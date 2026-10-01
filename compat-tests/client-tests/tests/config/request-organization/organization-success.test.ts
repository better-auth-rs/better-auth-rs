import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}) { return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body)}); }
async function call(ctx:any,mode:string,path:string,body:any,headers:Record<string,string>) {return mode==="http"?post(ctx,`/api/auth/organization/${path}`,body,headers):post(ctx,"/__test/query-native",{method:"POST",path:`/organization/${path}`,body,headers});}
for(const mode of ["http","native"]){
  compatScenario(`${mode}: Organization nested projections reach hooks while original bodies remain unchanged`,async ctx=>{
    const signup=await post(ctx,"/api/auth/sign-up/email",{name:"Nested schema",email:`nested-${mode}@query.example`,password:"fixture-password"});expect(signup.status).toBe(200);
    const headers={cookie:signup.headers.getSetCookie().map(value=>value.split(";",1)[0]).join("; ")};
    const response=await call(ctx,mode,"create",{name:"Nested org",slug:`nested-${mode}`},headers);expect(response.status).toBe(200);const organization=await response.json();
    const observed=[];
    async function operation(path:string,body:any,projection:any,phase:string){
      await post(ctx,"/__test/body-events",{});
      const response=await call(ctx,mode,path,body,headers);expect(response.status).toBe(200);const result=await response.json();
      const trace=(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;
      expect(trace.map((event:any)=>event.phase)).toEqual(["before","plugin.before",phase,"after"]);
      for(const event of trace){expect(event.body).toEqual(event.phase===phase?projection:body);expect(event.requestBody).toBe(mode==="http"?JSON.stringify(body):null);}
      observed.push({path,trace:trace.map((event:any)=>({...event,requestBody:event.requestBody===null?null:JSON.parse(event.requestBody)}))});return result;
    }
    const team=await operation("create-team",{organizationId:organization.id,name:"Original team",unknown:"raw"},{organizationId:organization.id,name:"Original team"},"team.create");
    const updated=await operation("update-team",{teamId:team.id,data:{organizationId:organization.id,name:"Updated team",unknown:"nested raw"},unknown:"raw"},{teamId:team.id,data:{organizationId:organization.id,name:"Updated team"}},"team.update");
    expect(updated.name).toBe("Updated team");
    const org=await operation("update",{organizationId:organization.id,data:{name:"Updated org",logo:null,unknown:"nested raw"},unknown:"raw"},{organizationId:organization.id,data:{name:"Updated org",logo:null}},"organization.update");
    expect(org.name).toBe("Updated org");expect(org.logo).toBeNull();
    const invitation=await operation("invite-member",{organizationId:organization.id,email:`invited-${mode}@query.example`,role:"member",teamId:team.id,resend:false,unknown:"raw"},{organizationId:organization.id,email:`invited-${mode}@query.example`,role:"member",teamId:team.id,resend:false},"invitation.create");
    expect(invitation.email).toBe(`invited-${mode}@query.example`);
    const unset=await call(ctx,mode,"set-active-team",{teamId:null,unknown:"raw"},headers);expect(unset.status).toBe(200);
    return observed;
  });
}
