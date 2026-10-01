import {expect,test} from "bun:test";
import {betterAuth} from "better-auth";
import {apiKey} from "@better-auth/api-key";
test("secondary API keys retain UTF-16, null, and stable signed-zero ordering",async()=>{
 const values=new Map<string,string>();
 const customStorage={get:async(key:string)=>values.get(key)??null,set:async(key:string,value:string)=>{values.set(key,value)},delete:async(key:string)=>{values.delete(key)}};
 const auth=betterAuth({secret:"cached-sort-contract-secret-at-least-32-characters",baseURL:"http://cache-sort.test",logger:{disabled:true},emailAndPassword:{enabled:true},plugins:[apiKey({storage:"secondary-storage",customStorage})]});
 const signup=await auth.api.signUpEmail({body:{email:"owner@cache-sort.test",name:"Owner",password:"password123"},returnHeaders:true});
 const headers=new Headers({cookie:signup.headers.getSetCookie().map((value:string)=>value.split(";",1)[0]).join("; ")});
 const owner=signup.response.user.id;
 const keys=["\ue000","\u{10000}","a",null,"A"].map((name,index)=>({id:`key-${index}`,name,referenceId:owner,configId:"default",key:`secret-${index}`,enabled:true,rateLimitEnabled:false,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()}));
 for(const [index,key] of keys.entries()){const remaining=[0,-0,1,-1,null][index];values.set(`api-key:by-id:${key.id}`,JSON.stringify({...key,remaining}).replace('"remaining":0',Object.is(remaining,-0)?'"remaining":-0':'"remaining":0'));}
 values.set(`api-key:by-ref:${owner}`,JSON.stringify(keys.map(key=>key.id)));
 for(const direction of ["asc","desc"]){
  const result=await auth.api.listApiKeys({headers,query:{sortBy:"name",sortDirection:direction}});
  const expected=[null,"A","a","\u{10000}","\ue000"];
  if(direction==="desc")expected.reverse();
  expect(result.total).toBe(5);expect(result.apiKeys.map((key:any)=>key.name)).toEqual(expected);
 }
 for(const direction of ["asc","desc"]){
  const result=await auth.api.listApiKeys({headers,query:{sortBy:"remaining",sortDirection:direction}});
  expect(result.apiKeys.map((key:any)=>key.name)).toEqual(direction==="asc"?["A",null,"\ue000","\u{10000}","a"]:["a","\ue000","\u{10000}",null,"A"]);
 }
});
