import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";

const sqlite=process.env.COMPAT_PROFILE==="request-query-sqlite";
async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}){return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body)});}
async function native(ctx:any,input:any){return post(ctx,"/__test/query-native",input);}
async function signup(ctx:any,name:string){const r=await post(ctx,"/api/auth/sign-up/email",{name,email:`${name.toLowerCase()}@remaining.example`,password:"password123"});expect(r.status).toBe(200);return {...(await r.json()).user,cookie:r.headers.getSetCookie().map(x=>x.split(";",1)[0]).join("; ")};}
async function clear(ctx:any){await post(ctx,"/__test/query-events",{});}
async function trace(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/query-events`)).json()).events;}

compatScenario("remaining route schemas reject before authentication and preserve raw after-hook query",async ctx=>{
  const cases:[string,any,string,any?][]=[
    ["/passkey/generate-register-options",{authenticatorAttachment:"other",name:7,context:null},'[query.authenticatorAttachment] Invalid option: expected one of "platform"|"cross-platform"; [query.name] Invalid input: expected string, received number; [query.context] Invalid input: expected string, received null'],
    ["/api-key/get",{configId:7,id:["one","two"]},"[query.configId] Invalid input: expected string, received number; [query.id] Invalid input: expected string, received array"],
    ["/reset-password/missing",{callbackURL:["/one","/two"]},"[query.callbackURL] Invalid input: expected string, received array"],
    ["/reset-password",{token:7},"[query.token] Invalid input: expected string, received number",{newPassword:"new-password123"}],
    ["/delete-user/callback",{token:[],callbackURL:7},"[query.token] Invalid input: expected string, received array; [query.callbackURL] Invalid input: expected string, received number"],
    ["/account-info",{accountId:"missing",extra:"strict"},'[query] Unrecognized key: "extra"'],
    ["/account-info",{useAccountCookie:"true"},"[query] Invalid input"],
    ["/organization/get-organization",{organizationId:7,organizationSlug:[]},"[query.organizationId] Invalid input: expected string, received number; [query.organizationSlug] Invalid input: expected string, received array"],
    ["/organization/get-full-organization",{membersLimit:[]},"[query.membersLimit] Invalid input"],
    ["/organization/get-invitation",{},"[query.id] Invalid input: expected string, received undefined"],
    ["/organization/list-invitations",{organizationId:null},"[query.organizationId] Invalid input: expected string, received null"],
    ["/organization/list-user-invitations",{email:7},"[query.email] Invalid input: expected string, received number"],
    ["/organization/list-teams",{organizationId:7},"[query.organizationId] Invalid input: expected string, received number"],
    ["/organization/list-user-teams",{userId:[],organizationId:7},"[query.userId] Invalid input: expected string, received array; [query.organizationId] Invalid input: expected string, received number"],
    ["/organization/list-team-members",{teamId:7},"[query.teamId] Invalid input: expected string, received number"],
    ["/organization/get-active-member-role",{userId:7,organizationId:null,organizationSlug:[]},"[query.userId] Invalid input: expected string, received number; [query.organizationId] Invalid input: expected string, received null; [query.organizationSlug] Invalid input: expected string, received array"],
    ["/organization/get-role",{organizationId:7},"[query.organizationId] Invalid input: expected string, received number; [query] Invalid input"],
    ["/organization/get-role",{roleName:""},"[query.roleName] Too small: expected string to have >=1 characters"],
    ["/organization/get-role",{roleId:""},"[query.roleId] Too small: expected string to have >=1 characters"],
    ["/organization/get-role",{roleName:"",roleId:""},"[query] Invalid input"],
    ["/organization/get-role",{roleName:7,roleId:""},"[query.roleId] Too small: expected string to have >=1 characters"],
    ["/organization/get-role",{roleName:"",roleId:7},"[query.roleName] Too small: expected string to have >=1 characters"],
    ["/organization/list-roles",null,"[query] Invalid input: expected object, received null"],
  ];
  const results=[];
  for(const [path,query,message,body] of cases){
    await clear(ctx);
    const response=await native(ctx,{path,query,headers:{},...(body?{method:"POST",body}:{})});
    expect(response.status).toBe(400);
    const result=await response.json();expect(result).toEqual({message,code:"VALIDATION_ERROR"});
    const events=await trace(ctx);expect(events.map((e:any)=>e.phase)).toEqual(["before","after"]);
    for(const event of events)expect(event.query).toEqual(query);
    results.push({path,body:result,events});
  }
  return results;
});

compatScenario("API-key query coercion and Organization role union project validated handler inputs",async ctx=>{
  const owner=await signup(ctx,"SchemaOwner");const headers={cookie:owner.cookie};
  for(const name of ["A","B","C"]){const r=await post(ctx,"/api/auth/api-key/create",{name},headers);expect(r.status).toBe(200);}
  const results=[];
  for(const [limit,expected] of [[null,0],[false,0],[[],0],[["2"],2],["0x2",2],[true,1]] as const){
    await clear(ctx);const query={limit,sortBy:"name",unknown:"raw"};
    const response=await native(ctx,{path:"/api-key/list",headers,query});expect(response.status).toBe(200);
    const body=await response.json();expect(body.total).toBe(3);expect(body.limit).toBe(expected);expect(body.apiKeys.map((key:any)=>key.name)).toEqual(["A","B","C"].slice(0,expected));
    const events=await trace(ctx);for(const e of events)expect(e.query).toEqual(query);
    results.push({query,names:body.apiKeys.map((key:any)=>key.name),total:body.total,limit:body.limit,events});
  }
  for(const [limit,message] of [[["1","2"],"Invalid input: expected number, received NaN"],[1.5,"Invalid input: expected int, received number"],[9007199254740992,"Too big: expected int to be <=9007199254740991"],["Infinity","Invalid input: expected number, received Infinity"]] as const){
    const response=await native(ctx,{path:"/api-key/list",headers:{},query:{limit,offset:-1}});expect(response.status).toBe(400);
    const body=await response.json();expect(body.message).toBe(`[query.limit] ${message}; [query.offset] Too small: expected number to be >=0`);results.push(body);
  }
  for(const path of ["/organization/get-role","/organization/list-roles"]){
    await clear(ctx);const missing=await native(ctx,{path,headers});expect(missing.status).toBe(400);
    const body=await missing.json();expect(body.code).toBe("NO_ACTIVE_ORGANIZATION");
    const events=await trace(ctx);expect(events.map((e:any)=>e.phase)).toEqual(["before","after"]);
    for(const event of events)expect(event.query).toEqual({$undefined:true});
    results.push({path,body,events});
  }
  const created=await post(ctx,"/api/auth/organization/create",{name:"Query role",slug:"query-role"},headers);expect(created.status).toBe(200);const org=await created.json();
  const role=await post(ctx,"/api/auth/organization/create-role",{organizationId:org.id,role:"reader",permission:{organization:["update"]}},headers);expect(role.status).toBe(200);const roleData=(await role.json()).roleData;
  const first=await native(ctx,{path:"/organization/get-role",headers,query:{organizationId:org.id,roleName:"reader",roleId:"missing",unknown:"strip"}});expect(first.status).toBe(200);const body=await first.json();expect(body.role).toBe("reader");results.push({role:body.role,permission:body.permission});
  const second=await native(ctx,{path:"/organization/get-role",headers,query:{organizationId:org.id,roleName:7,roleId:roleData.id,unknown:"strip"}});expect(second.status).toBe(200);const fallback=await second.json();expect(fallback.role).toBe("reader");results.push({role:fallback.role,permission:fallback.permission});
  const invalid=await fetch(`${ctx.baseURL}/api/auth/api-key/list?limit=1&limit=2`,{headers});expect(invalid.status).toBe(400);results.push(await invalid.json());
  return results;
});

compatScenario("pagination preserves memory slicing, SQLite errors, and Organization parseInt prefixes",async ctx=>{
  const users=[];for(const name of ["PaginationA","PaginationB","PaginationC"])users.push(await signup(ctx,name));
  const headers={cookie:users[0].cookie};
  const created=await post(ctx,"/api/auth/organization/create",{name:"Pagination",slug:"query-pagination"},headers);expect(created.status).toBe(200);const org=await created.json();
  for(const user of users.slice(1)){const r=await post(ctx,"/__test/query-member",{organizationId:org.id,userId:user.id,role:"member"});expect(r.status).toBe(200);}
  const results=[];
  for(const [field,value,memory,sql] of [["limit","-1",2,3],["offset","-1",1,3],["limit","1.5",1,0],["offset","1.5",2,0],["limit","Infinity",3,0],["limit","0x2",2,2]] as const){
    const search=new URLSearchParams({searchField:"name",searchOperator:"starts_with",searchValue:"Pagination",sortBy:"name",[field]:value});
    const response=await fetch(`${ctx.baseURL}/api/auth/admin/list-users?${search}`,{headers});expect(response.status).toBe(200);const body=await response.json();
    expect(body.users.length).toBe(sqlite?sql:memory);expect(body.total).toBe(sqlite&&sql===0?0:3);
    results.push({field,value,...body,users:body.users.map((user:any)=>user.name)});
  }
  for(const [value,memory,sql] of [["-1",2,3],["1.5",1,1],["2tail",2,2],["0x2",2,2],["invalid",3,3]] as const){
    const response=await native(ctx,{path:"/organization/get-full-organization",headers,query:{organizationId:org.id,membersLimit:value,unknown:"strip"}});expect(response.status).toBe(200);const body=await response.json();expect(body.members.length).toBe(sqlite?sql:memory);results.push({value,count:body.members.length});
  }
  for(const value of ["1.5","Infinity"]){
    const response=await fetch(`${ctx.baseURL}/api/auth/organization/list-members?organizationId=${org.id}&limit=${value}`,{headers});
    expect(response.status).toBe(sqlite?500:200);
    if(sqlite){expect(await response.text()).toBe("");results.push({value,status:500});}
    else{const body=await response.json();expect(body.members.length).toBe(value==="1.5"?1:3);results.push({value,count:body.members.length});}
  }
  return results;
});
