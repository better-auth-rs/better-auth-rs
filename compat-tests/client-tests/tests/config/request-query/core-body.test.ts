import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";

async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}){return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body),redirect:"manual"});}
async function native(ctx:any,path:string,body:any,headers:Record<string,string>={}){return post(ctx,"/__test/query-native",{path,body,method:"POST",headers});}
async function clear(ctx:any){await post(ctx,"/__test/body-events",{});}
async function trace(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;}

compatScenario("core body schemas aggregate issues before authentication",async(ctx:any)=>{
  const cases:[string,any,string][]=[
    ["/sign-up/email",null,"[body] Invalid input: expected object, received null; [body] Invalid input: expected record, received null"],
    ["/sign-up/email",{name:7,email:"invalid",password:"",image:null,rememberMe:"false"},"[body.name] Invalid input: expected string, received number; [body.email] Invalid email address; [body.password] Too small: expected string to have >=1 characters; [body.image] Invalid input: expected string, received null; [body.rememberMe] Invalid input: expected boolean, received string"],
    ["/request-password-reset",{email:"a..b@example.com",redirectTo:7},"[body.email] Invalid email address; [body.redirectTo] Invalid input: expected string, received number"],
    ["/change-password",{newPassword:7,currentPassword:null,revokeOtherSessions:"false"},"[body.newPassword] Invalid input: expected string, received number; [body.currentPassword] Invalid input: expected string, received null; [body.revokeOtherSessions] Invalid input: expected boolean, received string"],
    ["/change-password",{newPassword:"new-password",currentPassword:"fixture-password",revokeOtherSessions:"true"},"[body.revokeOtherSessions] Invalid input: expected boolean, received string"],
    ["/verify-password",{password:null},"[body.password] Invalid input: expected string, received null"],
    ["/sign-out",{callbackURL:7,disableRedirect:null,state:[]},"[body.callbackURL] Invalid input: expected string, received number; [body.disableRedirect] Invalid input: expected boolean, received null; [body.state] Invalid input: expected string, received array"],
  ];
  const results=[];
  for(const [path,body,message] of cases){
    await clear(ctx);const response=await native(ctx,path,body);expect(response.status).toBe(400);const error=await response.json();expect(error).toEqual({message,code:"VALIDATION_ERROR"});
    const events=await trace(ctx);expect(events.map((event:any)=>event.phase)).toEqual(["before","plugin.before","after"]);
    for(const event of events)expect(event.body).toEqual(body);
    results.push({path,error,events});
  }
  return results;
});

compatScenario("signup preserves passthrough fields and optional default omission in adapter hooks",async(ctx:any)=>{
  const body={name:"",email:"passthrough-body@example.com",password:"fixture-password",unknown:{nested:"kept"}};
  await clear(ctx);const response=await post(ctx,"/api/auth/sign-up/email",body);expect(response.status).toBe(200);
  const result=await response.json();expect(result.user.name).toBe("");
  const events=await trace(ctx);expect(events.map((event:any)=>event.phase)).toEqual(["before","plugin.before","hash","user.before","session.before","user.after","session.after","after"]);
  for(const event of events){expect(event.body).toEqual(body);expect(JSON.parse(event.requestBody)).toEqual(body);}
  return {status:response.status,name:result.user.name,events};
});

compatScenario("password sender and authenticated handlers receive stripped input while after hooks retain raw input",async(ctx:any)=>{
  const email="managed-body@example.com";
  const signup=await post(ctx,"/api/auth/sign-up/email",{name:"Managed",email,password:"fixture-password"});expect(signup.status).toBe(200);
  const headers={cookie:signup.headers.getSetCookie().map(value=>value.split(";",1)[0]).join("; ")};
  const cases:[string,any,any,string[]][]=[
    ["/request-password-reset",{email,unknown:"raw"},{email},["before","plugin.before","sender","after"]],
    ["/verify-password",{password:"fixture-password",unknown:"raw"},{password:"fixture-password"},["before","plugin.before","verify","after"]],
    ["/change-password",{newPassword:"changed-password",currentPassword:"fixture-password",revokeOtherSessions:false,unknown:"raw"},{newPassword:"changed-password",currentPassword:"fixture-password",revokeOtherSessions:false},["before","plugin.before","hash","verify","after"]],
    ["/sign-out",{state:"state",unknown:"raw"},{state:"state"},["before","plugin.before","session.delete.before","session.delete.after","after"]],
  ];
  const results=[];
  for(const [path,body,parsed,phases] of cases){
    await clear(ctx);const response=await native(ctx,path,body,headers);expect(response.status).toBe(200);
    const events=await trace(ctx);expect(events.map((event:any)=>event.phase)).toEqual(phases);
    for(const event of events)expect(event.body).toEqual(["before","plugin.before","after"].includes(event.phase)?body:parsed);
    results.push({path,status:response.status,events});
  }
  return results;
});
