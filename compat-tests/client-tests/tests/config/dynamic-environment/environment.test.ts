import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
const entry = JSON.parse(process.env.COMPAT_DYNAMIC_CASE!);
compatScenario(`URL environment precedence: ${entry.name}`, async ctx => {
 const response = await fetch(`${ctx.baseURL}/__test/dynamic-context`, {method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({...entry.input,calls:[]})});
 expect(response.status).toBe(200);
 const result=await response.json();
 if(entry.error) expect(result.initializationError).toMatchObject({thrown:true,kind:"BetterAuthError"});
 else {
  expect(result.initialized.baseURL).toBe(entry.expected);
  expect(result.final).toEqual(result.initialized);
  if(entry.extraOrigins) expect(result.initialized.origins.slice(-entry.extraOrigins.length)).toEqual(entry.extraOrigins);
  if(entry.secure) expect(result.initialized.cookie).toMatchObject({secure:true,name:"__Secure-better-auth.session_token"});
 }
 return result;
});
