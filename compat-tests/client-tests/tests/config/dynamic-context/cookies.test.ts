import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("Cookie attribute domains cannot replace the required cross-domain base URL", async ctx => {
  const rows=[];
  for (const options of [{defaultCookieDomain:".example.test"},{sessionCookieDomain:".example.test"}]) {
    const response=await fetch(`${ctx.baseURL}/__test/dynamic-context`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({crossSubdomain:true,...options,calls:[]})});
    const result=await response.json();
    expect(result.initializationError).toMatchObject({kind:"BetterAuthError",message:"baseURL is required when crossSubdomainCookies are enabled."});
    expect(result.events).toEqual([]);
    rows.push(result);
  }
  return rows;
});

compatScenario("Advanced cookie policy survives issuance, cache chunks, authentication and deletion", async ctx => {
  const response = await fetch(`${ctx.baseURL}/__test/dynamic-cookies`, {method:"POST"});
  expect(response.status).toBe(200);
  const result=await response.json();
  expect(result.signup.status).toBe(200);
  expect(result.session).toEqual({status:200,email:"cookies@example.test"});
  const token=result.signup.cookies.find((cookie:any)=>cookie.name==="__Secure-custom-token");
  expect(token.attributes).toMatchObject({path:"/auth",domain:".example.test","max-age":"604800",samesite:"lax",secure:true});
  expect(token.attributes.httponly).toBeUndefined();
  const chunks=result.signup.cookies.filter((cookie:any)=>cookie.name.startsWith("__Secure-custom-cache."));
  expect(chunks.length).toBeGreaterThan(1);
  for(const cookie of chunks) expect(cookie.attributes).toMatchObject({path:"/cache",httponly:true,"max-age":"90"});
  expect(result.logout.status).toBe(200);
  for(const cookie of result.logout.cookies) expect(cookie.attributes["max-age"]).toBe("0");
  for(const chunk of chunks) expect(result.logout.cookies.some((cookie:any)=>cookie.name===chunk.name && cookie.attributes.path==="/cache")).toBe(true);
  return result;
});
