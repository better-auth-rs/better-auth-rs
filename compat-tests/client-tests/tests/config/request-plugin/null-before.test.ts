import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
{ const mode="http";
 compatScenario(`${mode}: Username before hooks observe null before the core body schema`,async ctx=>{
  const endpoint=mode==="http"?"/api/auth/sign-up/email":"/__test/query-native";
  await fetch(`${ctx.baseURL}/__test/body-events`,{method:"POST",headers:{"content-type":"application/json"},body:"{}"});
  const response=await fetch(`${ctx.baseURL}${endpoint}`,{method:"POST",headers:{"content-type":"application/json",origin:ctx.baseURL},body:JSON.stringify(mode==="http"?null:{path:"/sign-up/email",method:"POST",body:null})});
  expect(response.status).toBe(500);expect(await response.text()).toBe("");
  const events=(await(await fetch(`${ctx.baseURL}/__test/body-events`)).json()).events;expect(events.map((event:any)=>event.phase)).toEqual(["before"]);expect(events[0].body).toBeNull();return events;
 });
}
