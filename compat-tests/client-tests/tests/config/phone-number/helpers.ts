import {expect} from "bun:test";
import {compatScenario} from "../../../support/scenario";
export type Context=Parameters<Parameters<typeof compatScenario>[1]>[0];
export const post=(ctx:Context,path:string,json:unknown,actor="primary")=>ctx.rawRequest({path:`/api/auth${path}`,method:"POST",json,actor});
export async function control(ctx:Context,body:unknown){const response=await fetch(`${ctx.baseURL}/__test/identity`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});expect(response.status).toBe(200);return response.json();}
export async function send(ctx:Context,phoneNumber:string,purpose="verify"){const sent=await post(ctx,purpose==="verify"?"/phone-number/send-otp":"/phone-number/request-password-reset",{phoneNumber});expect(sent.status).toBe(200);const messages=await control(ctx,{phoneNumber});const latest=messages.at(-1);expect(latest).toMatchObject({phoneNumber,purpose});expect(latest.code).toMatch(/^\d{6}$/);return latest.code as string;}
export function error(result:Awaited<ReturnType<typeof post>>,status:number,code:string){expect(result.status).toBe(status);expect(result.body).toMatchObject({code});}
