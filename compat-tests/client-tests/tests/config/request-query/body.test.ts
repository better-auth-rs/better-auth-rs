import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";

async function post(ctx:any,path:string,body:any,headers:Record<string,string>={}){return fetch(`${ctx.baseURL}${path}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL,...headers},body:JSON.stringify(body),redirect:"manual"});}
async function events(ctx:any){return(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;}
for(const transport of ["http-json","http-form","native","native-request"]){
  for(const mode of ["default","false","replace","invalid"]){
    compatScenario(`${transport} ${mode}: endpoint body projection preserves raw hook inputs`,async(ctx:any)=>{
      const email=`body-${transport}-${mode}@example.com`;
      const signup=await post(ctx,"/api/auth/sign-up/email",{name:"Body",email,password:"fixture-password"});expect(signup.status).toBe(200);
      await post(ctx,"/__test/body-events",{});
      const input:any={email,password:mode==="replace"?"wrong-password":"fixture-password",unknown:"original"};
      if(mode==="false")input.rememberMe=false;
      if(mode==="invalid")input.rememberMe="false";
      const raw={...input};if(transport==="http-form"&&mode==="false")raw.rememberMe="false";
      const headers={"x-body-mode":mode};
      let response:Response;
      if(transport.startsWith("http")){
        const form=transport==="http-form";
        response=await fetch(`${ctx.baseURL}/api/auth/sign-in/email`,{method:"POST",headers:{...headers,"content-type":form?"application/x-www-form-urlencoded":"application/json"},body:form?new URLSearchParams(Object.entries(input).map(([key,value])=>[key,String(value)])):JSON.stringify(input),redirect:"manual"});
      }else{
        response=await post(ctx,"/__test/query-native",{path:"/sign-in/email",method:"POST",body:input,headers,...(transport==="native-request"?{request:`${ctx.baseURL}/original-request`,requestBody:JSON.stringify({transportOnly:true})}:{})});
      }
      const invalid=mode==="invalid"||(transport==="http-form"&&mode==="false");
      expect(response.status).toBe(invalid?400:200);
      const result=await response.json();expect(result.code??null).toBe(invalid?"VALIDATION_ERROR":null);
      const trace=await events(ctx);
      expect(trace.map((event:any)=>event.phase)).toEqual(invalid?["before","plugin.before","after"]:["before","plugin.before","verify","session.before","session.after","after"]);
      const parsed={email,password:"fixture-password",...(mode==="replace"?{callbackURL:"/replaced"}:{}),rememberMe:mode!=="false"};
      const merged=mode==="replace"?{...raw,password:"fixture-password",callbackURL:"/replaced",added:"replacement"}:raw;
      for(const event of trace){
        expect(event.body).toEqual(event.phase==="after"?merged:["before","plugin.before"].includes(event.phase)?raw:parsed);
        expect(event.request).toBe(transport!=="native");
        expect(event.errorCode).toBe(event.phase==="after"&&invalid?"VALIDATION_ERROR":null);
        if(transport==="native")expect(event.requestBody).toBeNull();
        else if(transport==="native-request")expect(event.requestBody).toBe(JSON.stringify({transportOnly:true}));
        else if(transport==="http-form")expect(Object.fromEntries(new URLSearchParams(event.requestBody))).toEqual(raw);
        else expect(JSON.parse(event.requestBody)).toEqual(raw);
      }
      return {status:response.status,code:result.code??null,trace};
    });
  }
}

compatScenario("body validation precedes query validation for reset-password and OAuth callbacks",async(ctx:any)=>{
  const cases:[string,any,any,string][]=[
    ["/reset-password",{newPassword:7,token:[]},{token:7},"[body.newPassword] Invalid input: expected string, received number; [body.token] Invalid input: expected string, received array"],
    ["/reset-password",{newPassword:"valid-password"},{token:7},"[query.token] Invalid input: expected string, received number"],
    ["/callback/google",{code:7,error:[]},{state:7},"[body.code] Invalid input: expected string, received number; [body.error] Invalid input: expected string, received array"],
    ["/callback/google",{code:"code",unknown:"strip"},{state:7},"[query.state] Invalid input: expected string, received number"],
  ];
  const results=[];
  for(const [path,body,query,message] of cases){
    await post(ctx,"/__test/query-events",{});
    const response=await post(ctx,"/__test/query-native",{path,method:"POST",body,query,headers:{}});
    expect(response.status).toBe(400);const error=await response.json();expect(error).toEqual({code:"VALIDATION_ERROR",message});
    const trace=(await(await fetch(`${ctx.baseURL}/__test/query-events`)).json()).events;
    expect(trace.map((event:any)=>event.phase)).toEqual(["before","after"]);
    for(const event of trace)expect(event.query).toEqual(query);
    results.push({path,error,trace});
  }
  const response=await post(ctx,"/api/auth/reset-password?token=7",{newPassword:7});
  expect(response.status).toBe(400);const error=await response.json();expect(error.message).toBe("[body.newPassword] Invalid input: expected string, received number");results.push(error);
  const callback=await post(ctx,"/__test/query-native",{path:"/callback/google",method:"POST",body:{code:"body-code",state:"body-state",unknown:"strip"},query:{state:"query-state",unknown:"also-strip"},headers:{}});
  expect(callback.status).toBe(302);
  const location=new URL(callback.headers.get("location")!);expect(location.pathname).toBe("/api/auth/callback/google");expect(Object.fromEntries(location.searchParams)).toEqual({code:"body-code",state:"query-state"});
  results.push({status:callback.status,location:location.pathname,params:Object.fromEntries(location.searchParams)});
  return results;
});
