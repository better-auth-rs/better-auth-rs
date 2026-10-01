import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
async function call(ctx:any,input:any){const response=await fetch(`${ctx.baseURL}/__test/native-dispatch`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(input)});expect(response.status).toBe(200);return response.json();}
const input=(operation:string)=>operation==="createVerificationOTP"?{body:{email:"initial@example.test",type:"sign-in"}}:operation==="getVerificationOTP"?{query:{email:"initial@example.test",type:"sign-in"}}:operation==="signJWT"?{body:{payload:{sub:"initial"}}}:operation==="verifyJWT"?{body:{token:"invalid"}}:operation==="viewBackupCodes"?{body:{userId:"missing"}}:{body:{secret:"initial-secret",unknown:true}};
compatScenario("native facades execute before and after hooks, preserve Request and raw input, and retain private HTTP visibility",async ctx=>{
 const observations=[];
 for(const operation of ["generateTOTP","viewBackupCodes","createVerificationOTP","getVerificationOTP","signJWT","verifyJWT"]){
  const value=await call(ctx,{operation,...input(operation),headers:{"X-Literal":"observed"},request:true});
  expect(value.events[0]).toMatchObject({phase:"before",path:"/",ambient:{$undefined:true},request:"/original",header:"observed"});
  expect(value.events.at(-1).phase).toBe("plugin.after");
  if(operation==="generateTOTP")expect(value.result.code).toMatch(/^\d{6}$/);
  if(operation==="createVerificationOTP"){expect(value.result).toBe("123456");expect(value.events.find((e:any)=>e.phase==="generator")).toMatchObject({path:"virtual:",ambient:"virtual:",body:input(operation).body});}
  if(operation==="getVerificationOTP")expect(value.result).toEqual({otp:"123456"});
  if(operation==="verifyJWT")expect(value.result).toEqual({payload:null});
  if(operation==="viewBackupCodes")expect(value.error.status).toBe(400);
  if(operation==="signJWT"){const verified=await call(ctx,{operation:"verifyJWT",body:{token:value.result.token}});expect(verified.result.payload.sub).toBe("initial");}
  observations.push({operation,events:value.events,error:value.error??null});
 }
 for(const path of ["/generateTOTP","/signJWT","/createVerificationOTP"]){const r=await fetch(`${ctx.baseURL}/api/auth${path}`,{method:"POST",headers:{"content-type":"application/json"},body:"{}"});expect(r.status).toBe(404);}
 return observations;
});
compatScenario("native delayed context patches reach validators and persistence while later before hooks retain raw input",async ctx=>{
 const created=await call(ctx,{operation:"createVerificationOTP",mode:"patch",...input("createVerificationOTP")});expect(created.result).toBe("123456");
 expect(created.events[0].body.email).toBe("initial@example.test");expect(created.events[1].body.email).toBe("initial@example.test");
 expect(created.events.find((e:any)=>e.phase==="generator").body).toEqual({email:"PATCHED@example.test",type:"sign-in"});
 expect(created.events.at(-1).body).toEqual({email:"PATCHED@example.test",type:"sign-in",unknown:true});
 const stored=await call(ctx,{operation:"getVerificationOTP",query:{email:"patched@example.test",type:"sign-in"}});expect(stored.result).toEqual({otp:"123456"});
 const signed=await call(ctx,{operation:"signJWT",mode:"patch",...input("signJWT")});const verified=await call(ctx,{operation:"verifyJWT",body:{token:signed.result.token}});expect(verified.result.payload.sub).toBe("changed");
 return {created,stored,signEvents:signed.events,verified:verified.result.payload.sub};
});
compatScenario("native before short circuits and after replacements apply to every facade",async ctx=>{
 const result=[];
 for(const operation of ["generateTOTP","viewBackupCodes","createVerificationOTP","getVerificationOTP","signJWT","verifyJWT"]){for(const mode of ["stop","replace"]){
  const value=await call(ctx,{operation,mode,...input(operation)});
  if(mode==="stop")expect(value.events.map((e:any)=>e.phase)).toEqual(["before"]);else expect(value.events.at(-1).phase).toBe("plugin.after");
  if(operation==="createVerificationOTP"&&mode==="stop")expect(value.error).toEqual({status:400,body:{code:"STOPPED",message:"stopped"}});else expect(JSON.stringify(value.result)).toContain(mode==="stop"?"stopped":"replaced");result.push({operation,mode,...value});
 }}return result;
});
compatScenario("native validation API errors run after hooks and ordinary generation errors preserve the original failure",async ctx=>{
 const result=[];
 for(const operation of ["generateTOTP","createVerificationOTP","getVerificationOTP","signJWT","verifyJWT"]){const value=await call(ctx,{operation,mode:"invalid",...input(operation)});expect(value.error.status).toBe(400);expect(value.error.body.code).toBe("VALIDATION_ERROR");expect(value.events.map((e:any)=>e.phase)).toEqual(["before","plugin.before","after","plugin.after"]);result.push(value);}
 const ordinary=await call(ctx,{operation:"createVerificationOTP",mode:"ordinary",...input("createVerificationOTP")});expect(ordinary.error).toEqual({ordinary:true,message:"generator failed"});expect(ordinary.events.map((e:any)=>e.phase)).toEqual(["before","plugin.before","generator"]);const afterError=await call(ctx,{operation:"generateTOTP",mode:"after-error",...input("generateTOTP")});expect(afterError.error).toEqual({status:400,body:{code:"AFTER_REJECTION",message:"after rejection"}});expect(afterError.errorHeaders).toBe("retained");expect(afterError.events.map((event:any)=>event.phase)).toEqual(["before","plugin.before","after","plugin.after"]);return {result,ordinary,afterError};
});

compatScenario("native before patches replace signing option groups after validation",async ctx=>{
 const signed=await call(ctx,{operation:"signJWT",mode:"options",body:{payload:{sub:"fixture",iat:100}}});
 const claims=JSON.parse(Buffer.from(signed.result.token.split('.')[1],"base64url").toString());
 expect(claims).toMatchObject({sub:"fixture",iat:100,iss:"changed-issuer",aud:["one","two"],exp:220});
 expect(signed.events.at(-1).body.overrideOptions.jwt.expirationTime).toBe("2 minutes");
 return {claims,events:signed.events};
});
