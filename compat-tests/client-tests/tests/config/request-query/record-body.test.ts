import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";

async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}) {
  return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body)});
}
async function call(ctx:any,transport:string,path:string,body:any,headers:Record<string,string>={}) {
  return transport==="http"?post(ctx,`/api/auth${path}`,body,headers):post(ctx,"/__test/query-native",{path,method:"POST",body,headers});
}
async function clear(ctx:any) {await post(ctx,"/__test/body-events",{});}
async function trace(ctx:any) {return(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;}

compatScenario("user and session records validate before authentication through HTTP and native dispatch",async(ctx:any)=>{
  const results=[];
  for(const transport of ["http","native"]){
    for(const path of ["/update-user","/update-session"]){
      for(const [body,type] of [[undefined,"undefined"],[null,"null"],[[],"array"],[false,"boolean"],[7,"number"],["value","string"]] as const){
        await clear(ctx);
        const response=await call(ctx,transport,path,body);
        expect(response.status).toBe(400);
        const error=await response.json();
        expect(error).toEqual({code:"VALIDATION_ERROR",message:`[body] Invalid input: expected record, received ${type}`});
        const events=await trace(ctx);
        expect(events.map((event:any)=>event.phase)).toEqual(["before","plugin.before","after"]);
        for(const event of events)expect(event.body).toEqual(body===undefined?{$undefined:true}:body);
        results.push({transport,path,error,events});
      }
      const response=await call(ctx,transport,path,{});
      expect(response.status).toBe(401);
      results.push({transport,path,error:await response.json()});
    }
  }
  return results;
});

compatScenario("record projection preserves values and raw hooks while removing only the prototype setter",async(ctx:any)=>{
  const signup=await post(ctx,"/api/auth/sign-up/email",{name:"Initial",email:"record-body@example.com",password:"fixture-password"});
  expect(signup.status).toBe(200);
  const headers={cookie:signup.headers.getSetCookie().map(value=>value.split(";",1)[0]).join("; ")};
  const results=[];
  for(const transport of ["http","native"]){
    const body=JSON.parse('{"name":"Record '+transport+'","__proto__":{"removed":true},"constructor":{"kept":true},"unknown":{"nested":{"__proto__":7}}}');
    const projected=JSON.parse(JSON.stringify(body));delete projected.__proto__;
    await clear(ctx);
    const response=await call(ctx,transport,"/update-user",body,headers);
    expect(response.status).toBe(200);expect(await response.json()).toEqual({status:true});
    const events=await trace(ctx);
    expect(events.map((event:any)=>event.phase)).toEqual(["before","plugin.before","user.update.before","user.update.after","after"]);
    for(const event of events)expect(event.body).toEqual(event.phase.startsWith("user.update.")?projected:body);
    const cookie=response.headers.getSetCookie().map(value=>value.split(";",1)[0]).join("; ");
    expect(cookie.length).toBeGreaterThan(0);
    const session=await(await fetch(`${ctx.baseURL}/api/auth/get-session`,{headers:{cookie}})).json();
    expect(session.user.name).toBe(body.name);
    results.push({transport,events,name:session.user.name});
    const noFields=await call(ctx,transport,"/update-session",{unknown:body.unknown},headers);
    expect(noFields.status).toBe(400);expect(await noFields.json()).toEqual({message:"No fields to update"});
  }
  return results;
});

compatScenario("user update rejects truthy email changes and ignores explicit falsy email values",async(ctx:any)=>{
  const signup=await post(ctx,"/api/auth/sign-up/email",{name:"Initial",email:"record-email@example.com",password:"fixture-password"});
  expect(signup.status).toBe(200);
  const headers={cookie:signup.headers.getSetCookie().map(value=>value.split(";",1)[0]).join("; ")};
  const results=[];
  for(const transport of ["http","native"]){
    for(const email of [null,false,0,"",[],{},"replacement@example.com"]){
      const response=await call(ctx,transport,"/update-user",{name:"Email unchanged",email},headers);
      const rejected=Array.isArray(email)||typeof email==="object"&&email!==null||email==="replacement@example.com";
      expect(response.status).toBe(rejected?400:200);
      const result=await response.json();
      expect(result).toEqual(rejected?{code:"EMAIL_CAN_NOT_BE_UPDATED",message:"Email can not be updated"}:{status:true});
      results.push({transport,email,result});
    }
  }
  const session=await(await fetch(`${ctx.baseURL}/api/auth/get-session?disableCookieCache=true`,{headers})).json();
  expect(session.user.email).toBe("record-email@example.com");
  return results;
});
