import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

async function control(ctx:any,path:string,body:unknown){return fetch(`${ctx.baseURL}/__test/${path}`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});}
async function clear(ctx:any){await control(ctx,"query-events",{});}
async function events(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/query-events`)).json()).events;}
async function native(ctx:any,input:unknown){return control(ctx,"query-native",input);}
async function observed(ctx:any,response:Response){return{status:response.status,body:await response.json(),events:await events(ctx)};}
function cookie(response:Response){return response.headers.getSetCookie().map(value=>value.split(";",1)[0]).join("; ");}

compatScenario("raw query preserves duplicates, empty values, literal bracket names, and native omission",async ctx=>{
  const output=[];
  for(const [search,query] of [
    ["value=one&value=two&value=",{value:["one","two",""]}],
    ["value%5B%5D=one&value%5B%5D=two&value=plain",{"value[]":["one","two"],value:"plain"}],
    ["value=a+b&value=a%2Bb&value=%E2%9C%93",{value:["a b","a+b","✓"]}],
    ["",{}],
  ] as const){
    await clear(ctx);
    const path=`/api/auth/query/raw${search?`?${search}`:""}`;
    const result=await observed(ctx,await fetch(`${ctx.baseURL}${path}`));
    expect(result.status).toBe(200);expect(result.body).toEqual({query,url:path});
    expect(result.events).toEqual(["before","endpoint","after"].map(phase=>({phase,path:"/query/raw",query,url:path})));
    output.push(result);
  }
  for(const input of [{}, {query:null}, {query:["one",2,null]}, {query:{value:["one",2,true,null,{nested:"value"}]}}, {request:"http://original.example/original?value=url&value=second"}, {request:"http://original.example/original?value=url&value=second",query:{value:["explicit",3]}}]){
    await clear(ctx);
    const result=await observed(ctx,await native(ctx,{path:"/query/raw",...input}));
    const query=Object.hasOwn(input,"query")?(input as any).query:{$undefined:true};
    const url=Object.hasOwn(input,"request")?"/original?value=url&value=second":null;
    expect(result.body).toEqual({query,url});
    expect(result.events).toEqual(["before","endpoint","after"].map(phase=>({phase,path:"/query/raw",query,url})));
    output.push(result);
  }
  return output;
});

compatScenario("query schema scope preserves raw hooks and original Request while handler receives coerced fields",async ctx=>{
  const output=[];
  await clear(ctx);
  const path="/api/auth/query/validated?disableCookieCache=&disableCookieCache=&disableRefresh=false&unknown=raw";
  const raw={disableCookieCache:["",""],disableRefresh:"false",unknown:"raw"};
  const result=await observed(ctx,await fetch(`${ctx.baseURL}${path}`));
  expect(result.body).toEqual({query:{disableCookieCache:true,disableRefresh:true},url:path});
  expect(result.events).toEqual([
    {phase:"before",path:"/query/validated",query:raw,url:path},
    {phase:"endpoint",path:"/query/validated",query:{disableCookieCache:true,disableRefresh:true},url:path},
    {phase:"after",path:"/query/validated",query:raw,url:path},
  ]);output.push(result);
  await clear(ctx);
  const input={path:"/query/validated",query:{disableCookieCache:false,unknown:"raw"},request:"http://original.example/original?unknown=transport"};
  const projected=await observed(ctx,await native(ctx,input));
  expect(projected.body).toEqual({query:{disableCookieCache:false},url:"/original?unknown=transport"});
  expect(projected.events.map((event:any)=>event.query)).toEqual([input.query,{disableCookieCache:false},input.query]);output.push(projected);
  for(const query of [null,[],{disableCookieCache:[]}] as const){
    await clear(ctx);
    const invalid=await observed(ctx,await native(ctx,{path:"/query/validated",query}));
    if(query===null||Array.isArray(query)){
      expect(invalid.status).toBe(400);
      expect(invalid.body).toEqual({code:"VALIDATION_ERROR",message:`[query] Invalid input: expected object, received ${query===null?"null":"array"}`});
      expect(invalid.events.map((event:any)=>event.phase)).toEqual(["before","after"]);
    }else{expect(invalid.body.query).toEqual({disableCookieCache:true});}
    expect(invalid.events[0].query).toEqual(query);expect(invalid.events.at(-1).query).toEqual(query);output.push(invalid);
  }
  return output;
});

compatScenario("actual user and member listings retain array filters through storage and validate before authentication",async ctx=>{
  const users=[];
  for(const name of ["Query Owner","Query Alpha","Query Beta"]){
    const response=await fetch(`${ctx.baseURL}/api/auth/sign-up/email`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name,email:`${name.toLowerCase().replaceAll(" ","-")}@query.example`,password:"password123"})});
    expect(response.status).toBe(200);users.push({...((await response.json()).user),cookie:cookie(response)});
  }
  const owner=users[0];
  const created=await fetch(`${ctx.baseURL}/api/auth/organization/create`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,cookie:owner.cookie},body:JSON.stringify({name:"Query",slug:"query-boundary"})});
  expect(created.status).toBe(200);const org=await created.json();
  for(const user of users.slice(1)){const response=await control(ctx,"query-member",{organizationId:org.id,userId:user.id,role:user.name==="Query Alpha"?"admin":"member"});expect(response.status).toBe(200);}
  const output=[];
  for(const [path,field,values,key] of [["/admin/list-users","name",["Query Alpha","Query Beta"],"users"],["/organization/list-members","role",["admin","member"],"members"]] as const){
    const search=new URLSearchParams({organizationId:org.id,filterField:field,filterOperator:"in",sortBy:field,sortDirection:"asc",unknown:"preserved"});for(const value of values)search.append("filterValue",value);
    await clear(ctx);
    const listed=await observed(ctx,await fetch(`${ctx.baseURL}/api/auth${path}?${search}`,{headers:{cookie:owner.cookie}}));
    expect(listed.status).toBe(200);expect(listed.body.total).toBe(2);expect(listed.body[key]).toHaveLength(2);
    expect(listed.body[key].map((row:any)=>key==="users"?row.id:row.userId).sort()).toEqual(users.slice(1).map(user=>user.id).sort());
    for(const event of listed.events){expect(event.query.filterValue).toEqual(values);expect(event.query.unknown).toBe("preserved");expect(event.url).toBe(`/api/auth${path}?${search}`);event.url=event.url.replace(org.id,"<organizationId>");}
    output.push(listed);
    await clear(ctx);
    const excluded=await observed(ctx,await native(ctx,{path,headers:{cookie:owner.cookie},query:{organizationId:org.id,filterField:field,filterOperator:"not_in",filterValue:values,...(key==="users"?{searchField:"name",searchOperator:"starts_with",searchValue:"Query "}:{})}}));
    expect(excluded.status).toBe(200);expect(excluded.body.total).toBe(1);
    expect(key==="users"?excluded.body[key][0].id:excluded.body[key][0].userId).toBe(owner.id);output.push(excluded);
    for(const filterValue of [["mixed",7],[true,false]]){
      await clear(ctx);
      const invalid=await observed(ctx,await native(ctx,{path,headers:{},query:{filterValue}}));
      expect(invalid.status).toBe(400);expect(invalid.body).toEqual({code:"VALIDATION_ERROR",message:"[query.filterValue] Invalid input"});
      expect(invalid.events.map((event:any)=>event.phase)).toEqual(["before","after"]);expect(invalid.events[1].query.filterValue).toEqual(filterValue);output.push(invalid);
    }
  }
  await control(ctx,"query-user",{id:owner.id,name:"Query Fresh"});
  const stale=await native(ctx,{path:"/get-session",headers:{cookie:owner.cookie},query:{disableCookieCache:false}});expect((await stale.json()).user.name).toBe("Query Owner");
  await clear(ctx);
  const fresh=await observed(ctx,await fetch(`${ctx.baseURL}/api/auth/get-session?disableCookieCache=&disableCookieCache=&unknown=raw`,{headers:{cookie:owner.cookie}}));
  expect(fresh.status).toBe(200);expect(fresh.body.user.name).toBe("Query Fresh");
  expect(fresh.events.map((event:any)=>event.query)).toEqual([{disableCookieCache:["",""],unknown:"raw"},{disableCookieCache:["",""],unknown:"raw"}]);output.push(fresh);
  await clear(ctx);
  const missing=await observed(ctx,await native(ctx,{path:"/admin/list-users",headers:{}}));
  expect(missing.status).toBe(400);expect(missing.body.message).toBe("[query] Invalid input: expected object, received undefined");output.push(missing);
  await clear(ctx);
  const repeatedId=await observed(ctx,await fetch(`${ctx.baseURL}/api/auth/admin/get-user?id=one&id=two`));
  expect(repeatedId.status).toBe(400);expect(repeatedId.body.message).toBe("[query.id] Invalid input: expected string, received array");output.push(repeatedId);
  return output;
});
