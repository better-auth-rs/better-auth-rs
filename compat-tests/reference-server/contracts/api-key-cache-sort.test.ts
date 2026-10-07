import {expect,test} from "bun:test";
import {betterAuth} from "better-auth";
import {apiKey} from "@better-auth/api-key";
test("secondary API keys retain UTF-16, null, and stable signed-zero ordering",async()=>{
 const values=new Map<string,string>();
 const mutations:string[]=[];
 const customStorage={get:async(key:string)=>values.get(key)??null,set:async(key:string,value:string)=>{mutations.push(`set:${key}`);values.set(key,value)},delete:async(key:string)=>{mutations.push(`delete:${key}`);values.delete(key)}};
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
 for(const {names,ascending,descending} of [
  {names:[42],ascending:[0],descending:[0]},
  {names:[10,2],ascending:[1,0],descending:[0,1]},
  {names:[2,"2","10"],ascending:[0,2,1],descending:[0,1,2]},
  {names:[2,"word",1],ascending:[0,1,2],descending:[0,1,2]},
  {names:[10,"2",2,null,undefined,null,10],ascending:[3,4,5,1,2,0,6],descending:[0,6,1,2,3,4,5]},
  {names:[{},{valueOf:null},{nested:{toString:null}},JSON.parse('{"__proto__":{"toString":null}}')],ascending:[0,1,2,3],descending:[0,1,2,3]},
  {names:[[{valueOf:null}],"[object Object]"],ascending:[0,1],descending:[0,1]},
  {names:[{toString:null}],ascending:[0],descending:[0]},
  {names:[{toString:null},null],ascending:[1,0],descending:[0,1]},
  {names:[{toString:null},undefined],ascending:[1,0],descending:[0,1]},
 ]){
  values.clear();
  const records=names.map((name,index)=>({...keys[0],id:`dynamic-${index}`,key:`dynamic-secret-${index}`,name}));
  for(const key of records)values.set(`api-key:by-id:${key.id}`,JSON.stringify(key));
  values.set(`api-key:by-ref:${owner}`,JSON.stringify(records.map(key=>key.id)));
  for(const direction of ["asc","desc"]){
   const result=await auth.api.listApiKeys({headers,query:{sortBy:"name",sortDirection:direction}});
   const expected=direction==="asc"?ascending:descending;
   expect(result.total).toBe(names.length);
   expect(result.apiKeys.map((key:any)=>[key.id,key.name,Object.hasOwn(key,"name")])).toStrictEqual(expected.map(index=>[`dynamic-${index}`,names[index],names[index]!==undefined]));
  }
 }
 for(const value of [{toString:null},{toString:false},{toString:0},{toString:""},{toString:[]},{toString:{}},[{toString:null}]]){
  for(const names of [[value,"x"],["x",value]]){
   values.clear();mutations.length=0;
   const records=names.map((name,index)=>({...keys[0],id:`object-${index}`,key:`object-secret-${index}`,name}));
   for(const key of records)values.set(`api-key:by-id:${key.id}`,JSON.stringify(key));
   values.set(`api-key:by-ref:${owner}`,JSON.stringify(records.map(key=>key.id)));
   const before=[...values];
   for(const direction of ["asc","desc"]){
    await expect(auth.api.listApiKeys({headers,query:{sortBy:"name",sortDirection:direction}})).rejects.toBeInstanceOf(TypeError);
    expect([...values]).toStrictEqual(before);
    expect(mutations).toStrictEqual([]);
   }
   const unsorted=await auth.api.listApiKeys({headers});
   expect(unsorted.total).toBe(names.length);
   expect(unsorted.apiKeys.map((key:any)=>[key.id,key.name])).toStrictEqual(names.map((name,index)=>[`object-${index}`,name]));
   expect([...values]).toStrictEqual(before);
   expect(mutations).toStrictEqual([]);
  }
 }
 for(const field of ["createdAt","updatedAt","expiresAt","lastRequest","lastRefillAt"] as const){
  values.clear();
  const dates=["2099-10-02T00:00:00.000Z","invalid-date","2099-10-01T00:00:00.000Z"];
  const records=dates.map((date,index)=>({...keys[0],id:`date-${index}`,key:`date-secret-${index}`,[field]:date}));
  for(const key of records)values.set(`api-key:by-id:${key.id}`,JSON.stringify(key));
  values.set(`api-key:by-ref:${owner}`,JSON.stringify(records.map(key=>key.id)));
  for(const direction of ["asc","desc"]){
   const result=await auth.api.listApiKeys({headers,query:{sortBy:field,sortDirection:direction}});
   expect(result.total).toBe(dates.length);
   expect(Number.isNaN(result.apiKeys[1][field]!.getTime())).toBe(true);
   expect(JSON.parse(JSON.stringify(result.apiKeys)).map((key:any)=>[key.id,key[field]])).toStrictEqual([["date-0",dates[0]],["date-1",null],["date-2",dates[2]]]);
  }
 }
});
