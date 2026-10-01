import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";

compatScenario("Native organization creation distinguishes omitted headers from an unauthenticated request",async ctx=>{
  const post=(path:string,body:any)=>fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL},body:JSON.stringify(body)});
  const signup=await post("/api/auth/sign-up/email",{name:"Native owner",email:"native-owner@query.example",password:"fixture-password"});
  expect(signup.status).toBe(200);const {user}=await signup.json();
  const native=(path:string,body:any,extra:any={})=>post("/__test/query-native",{method:"POST",path:`/organization/${path}`,body,...extra});
  const body={name:"Server organization",slug:"server-organization",userId:user.id,unknown:"raw"};
  const rejected=[];
  for(const extra of [{headers:{}},{request:`${ctx.baseURL}/api/auth/organization/create`}]){
    const response=await native("create",body,extra);expect(response.status).toBe(401);rejected.push(await response.json());
  }
  const http=await post("/api/auth/organization/create",body);expect(http.status).toBe(401);rejected.push(await http.json());
  const absentUser=await native("create",{name:"Missing",slug:"missing"});expect(absentUser.status).toBe(401);rejected.push(await absentUser.json());
  const slug=await native("check-slug",{slug:body.slug,unknown:"raw"});expect(slug.status).toBe(200);expect(await slug.json()).toEqual({status:true});
  const slugHeaders=await native("check-slug",{slug:body.slug},{headers:{}});expect(slugHeaders.status).toBe(401);rejected.push(await slugHeaders.json());
  const created=await native("create",body);expect(created.status).toBe(200);const organization=await created.json();
  expect(organization.name).toBe(body.name);expect(organization.members).toHaveLength(1);expect(organization.members[0].userId).toBe(user.id);
  const explicit=await native("create",{...body,slug:"explicit-null-logo",logo:null});expect(explicit.status).toBe(200);const nullLogo=await explicit.json();expect(nullLogo.logo).toBeNull();
  expect(organization).not.toHaveProperty("userId");expect(organization).not.toHaveProperty("unknown");
  const cookie=signup.headers.getSetCookie().map(value=>value.split(";",1)[0]).join("; ");
  const list=await fetch(`${ctx.baseURL}/api/auth/organization/list`,{headers:{cookie}});expect(list.status).toBe(200);expect((await list.json()).map((value:any)=>value.id).sort()).toEqual([organization.id,nullLogo.id].sort());
  return {rejected,organization,nullLogo};
});
