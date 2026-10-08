import {expect,test} from "bun:test";
import {betterAuth} from "better-auth";
import {apiKey} from "@better-auth/api-key";
import { memoryAdapter } from "better-auth/adapters/memory";
import { testUtils } from "better-auth/plugins";
import { readFileSync } from "node:fs";
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

function rawCache() {
 const values = new Map<string, unknown>();
 const reads: string[] = [];
 const writes: unknown[] = [];
 const cache = {
  values, reads, writes,
  beforeRead: undefined as undefined | ((key: string) => Promise<void>),
  async get(key: string) { reads.push(key); await cache.beforeRead?.(key); return values.get(key) ?? null; },
  async set(key: string, value: string) { writes.push(["set", key, value]); values.set(key, value); },
  async delete(key: string) { writes.push(["delete", key]); values.delete(key); },
 };
 return cache;
}

async function rawListHarness(configurations: Parameters<typeof apiKey>[0]) {
 for (const name of ["better-auth", "@better-auth/core", "@better-auth/api-key"]) {
  expect(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version).toBe("1.7.6");
 }
 const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], apikey: [] };
 const auth = betterAuth({
  database: memoryAdapter(memory), baseURL: "http://raw-cache-list.test",
  secret: "raw-cache-list-contract-at-least-32-characters", logger: { disabled: true },
  telemetry: { enabled: false }, rateLimit: { enabled: false }, plugins: [apiKey(configurations), testUtils()],
 });
 const context = await auth.$context;
 const date = new Date("2030-01-02T03:04:05.000Z");
 await context.adapter.create({ model: "user", forceAllowId: true, data: {
  id: "owner", name: "Owner", email: "owner@raw-cache-list.test", emailVerified: true, createdAt: date, updatedAt: date,
 } });
 const { headers } = await context.test.login({ userId: "owner" });
 return { auth, headers, memory };
}

const rawIndex = "api-key:by-ref:owner";
const rawDate = "2030-01-02T03:04:05.000Z";
const ordinaryRawRecord = { referenceId: "owner", configId: "second", key: "secret", createdAt: rawDate, updatedAt: rawDate };
const ordinaryRawResponse = { referenceId: "owner", configId: "second", createdAt: rawDate, updatedAt: rawDate, expiresAt: null, lastRefillAt: null, lastRequest: null, metadata: null, permissions: null };

test("raw list results consume group IDs before owner filtering and preserve explicit configuration duplicates", async () => {
 const first = rawCache();
 const second = rawCache();
 const { auth, headers, memory } = await rawListHarness([
  { configId: "default", storage: "secondary-storage", customStorage: first },
  { configId: "second", storage: "secondary-storage", customStorage: second },
 ]);
 second.values.set(rawIndex, '["without-id"]');
 second.values.set("api-key:by-id:without-id", JSON.stringify(ordinaryRawRecord));
 const stored = structuredClone(memory);
 for (const length of ["0", false, "", "-1", "0.5", "word", [], {}]) {
  first.values.set(rawIndex, JSON.stringify({ length }));
  first.reads.length = 0; second.reads.length = 0;
  const before = [[...first.values], [...second.values]];
  const response = await auth.api.listApiKeys({ headers });
  expect(JSON.parse(JSON.stringify(response))).toStrictEqual({ apiKeys: [], total: 0 });
  expect(first.reads).toStrictEqual([rawIndex]);
  expect(second.reads).toStrictEqual([rawIndex, "api-key:by-id:without-id"]);
  expect([[...first.values], [...second.values]]).toStrictEqual(before);
  expect([first.writes, second.writes]).toStrictEqual([[], []]);
  expect(memory).toStrictEqual(stored);
 }
 for (const source of ['{}', '{"length":null}', '{"length":0}']) {
  first.values.set(rawIndex, source);
  const response = await auth.api.listApiKeys({ headers });
  expect(JSON.parse(JSON.stringify(response))).toStrictEqual({ apiKeys: [ordinaryRawResponse], total: 1 });
 }
 second.values.set(rawIndex, '["without-id","without-id","without-id"]');
 for (const configId of [undefined, "second"]) {
  const response = await auth.api.listApiKeys({ headers, query: { configId, limit: "1", offset: "1" } });
  expect(JSON.parse(JSON.stringify(response))).toStrictEqual(configId
   ? { apiKeys: [ordinaryRawResponse], total: 3, limit: 1, offset: 1 }
   : { apiKeys: [], total: 1, limit: 1, offset: 1 });
 }
 expect([first.writes, second.writes]).toStrictEqual([[], []]);
 expect(memory).toStrictEqual(stored);
});

test("raw UTF-16 reference objects and serialized cache records retain separate date boundaries", async () => {
 const cache = rawCache();
 const { auth, headers, memory } = await rawListHarness({ storage: "secondary-storage", customStorage: cache });
 const raw = {
  id: "raw-id", referenceId: "owner", configId: "default", key: "hidden", name: "\ud800",
  createdAt: "raw-date", updatedAt: null, expiresAt: "still-raw", lastRefillAt: 0,
  metadata: { native: true }, permissions: '{"resource":["read"]}', extra: [1, { nested: true }],
 };
 cache.values.set(rawIndex, JSON.stringify({ length: raw }).replace('\\ud800', '\ud800'));
 const before = [...cache.values];
 const stored = structuredClone(memory);
 const response = await auth.api.listApiKeys({ headers });
 expect(response).toStrictEqual({ apiKeys: [{
  id: "raw-id", referenceId: "owner", configId: "default", name: "\ud800",
  createdAt: "raw-date", updatedAt: null, expiresAt: "still-raw", lastRefillAt: 0,
  metadata: { native: true }, permissions: { resource: ["read"] }, extra: [1, { nested: true }],
 }], total: 1, limit: undefined, offset: undefined });
 expect(Object.keys(response.apiKeys[0])).toStrictEqual([
  "id", "referenceId", "configId", "name", "createdAt", "updatedAt", "expiresAt", "lastRefillAt", "metadata", "permissions", "extra",
 ]);
 expect(cache.reads).toStrictEqual([rawIndex]);
 expect([...cache.values]).toStrictEqual(before);
 cache.values.clear(); cache.reads.length = 0;
 cache.values.set(rawIndex, '["\ud800"]');
 cache.values.set("api-key:by-id:\ud800", JSON.stringify({ ...ordinaryRawRecord, id: "\ud800", configId: "default", createdAt: "2030-01-02T11:04:05.000+08:00" }).replace('\\ud800', '\ud800'));
 const encoded = [...cache.values];
 const cached = await auth.api.listApiKeys({ headers });
 expect(cached.apiKeys[0].createdAt).toBeInstanceOf(Date);
 expect(JSON.parse(JSON.stringify(cached))).toStrictEqual({ apiKeys: [{ ...ordinaryRawResponse, id: "\ud800", configId: "default" }], total: 1 });
 expect(Object.keys(cached.apiKeys[0])).toStrictEqual([
  "referenceId", "configId", "createdAt", "updatedAt", "id", "expiresAt", "lastRefillAt", "lastRequest", "metadata", "permissions",
 ]);
 expect(cache.reads).toStrictEqual([rawIndex, "api-key:by-id:\ud800"]);
 expect([...cache.values]).toStrictEqual(encoded);
 expect(cache.writes).toStrictEqual([]);
 expect(memory).toStrictEqual(stored);
});

test("array-like lengths preserve native constructor errors and fallback guards", async () => {
 for (const fallbackToDatabase of [false, true]) {
  const cache = rawCache();
  const { auth, headers, memory } = await rawListHarness({ storage: "secondary-storage", customStorage: cache, fallbackToDatabase });
  const stored = structuredClone(memory);
  for (const source of ['{"length":1.5}', '{"length":1e999}', '{"length":4294967296}']) {
   cache.values.set(rawIndex, source); cache.reads.length = 0;
   await expect(auth.api.listApiKeys({ headers })).rejects.toThrow("Array length must be a positive integer of safe magnitude.");
   expect(cache.reads).toStrictEqual([rawIndex]);
   expect([...cache.values]).toStrictEqual([[rawIndex, source]]);
   expect(cache.writes).toStrictEqual([]);
  }
  for (const source of ['{"length":"0"}', '{"length":"0.5"}']) {
   cache.values.set(rawIndex, source); cache.reads.length = 0;
   const response = await auth.api.listApiKeys({ headers });
   expect(JSON.parse(JSON.stringify(response))).toStrictEqual({ apiKeys: [], total: 0 });
   expect(cache.reads).toStrictEqual([rawIndex]);
   expect([...cache.values]).toStrictEqual([[rawIndex, source]]);
   expect(cache.writes).toStrictEqual([]);
  }
  cache.values.set(rawIndex, '{"length":-1}');
  if (fallbackToDatabase) expect(JSON.parse(JSON.stringify(await auth.api.listApiKeys({ headers })))).toStrictEqual({ apiKeys: [], total: 0 });
  else await expect(auth.api.listApiKeys({ headers })).rejects.toThrow("Array length must be a positive integer of safe magnitude.");
  expect(cache.writes).toStrictEqual([]);
  expect(memory).toStrictEqual(stored);
 }
});

test("fractional string length uses one mapper worker for two indexed cache reads", async () => {
 const cache = rawCache();
 const { auth, headers, memory } = await rawListHarness({ storage: "secondary-storage", customStorage: cache });
 cache.values.set(rawIndex, '{"length":"1.5","0":"first","1":"second"}');
 const slots = ["first", "second"].map(id => {
  cache.values.set(`api-key:by-id:${id}`, JSON.stringify({ ...ordinaryRawRecord, id, configId: "default" }));
  return { id, start: Promise.withResolvers<void>(), release: Promise.withResolvers<void>() };
 });
 cache.beforeRead = async key => {
  const slot = slots.find(slot => key === `api-key:by-id:${slot.id}`);
  if (slot) { slot.start.resolve(); await slot.release.promise; }
 };
 const before = [...cache.values];
 const stored = structuredClone(memory);
 const pending = auth.api.listApiKeys({ headers });
 await slots[0].start.promise;
 expect(cache.reads).toStrictEqual([rawIndex, "api-key:by-id:first"]);
 slots[0].release.resolve();
 await slots[1].start.promise;
 expect(cache.reads).toStrictEqual([rawIndex, "api-key:by-id:first", "api-key:by-id:second"]);
 slots[1].release.resolve();
 const response = await pending;
 expect(JSON.parse(JSON.stringify(response))).toStrictEqual({ apiKeys: slots.map(({ id }) => ({ ...ordinaryRawResponse, id, configId: "default" })), total: 2 });
 expect([...cache.values]).toStrictEqual(before);
 expect(cache.writes).toStrictEqual([]);
 expect(memory).toStrictEqual(stored);
});

test("group rejection preserves the first error while independent groups finish queued reads", async () => {
 const groups = Array.from({ length: 3 }, (_, group) => {
  const cache = rawCache();
  const starts: number[] = [];
  const finishes: number[] = [];
  const slots = Array.from({ length: 12 }, (_, row) => ({
   id: `group-${group}-key-${row}`,
   started: Promise.withResolvers<void>(),
   release: Promise.withResolvers<void>(),
   finished: Promise.withResolvers<void>(),
  }));
  for (const { id } of slots) cache.values.set(`api-key:by-id:${id}`, JSON.stringify({
   ...ordinaryRawRecord, id, configId: `group-${group}`,
  }));
  cache.values.set(rawIndex, JSON.stringify(slots.map(slot => slot.id)));
  cache.beforeRead = async key => {
   const row = slots.findIndex(slot => key === `api-key:by-id:${slot.id}`);
   if (row < 0) return;
   starts.push(row);
   const slot = slots[row];
   slot.started.resolve();
   try { await slot.release.promise; }
   finally { finishes.push(row); slot.finished.resolve(); }
  };
  return { cache, slots, starts, finishes, before: [...cache.values] };
 });
 const { auth, headers, memory } = await rawListHarness(groups.map(({ cache }, group) => ({
  configId: `group-${group}`, storage: "secondary-storage", customStorage: cache,
 })));
 const stored = structuredClone(memory);
 const first = new Error("first group rejection");
 const later = new TypeError("later group rejection");
 const outcome = auth.api.listApiKeys({ headers }).then(result => result, error => error);
 await Promise.all(groups.flatMap(group => group.slots.slice(0, 10).map(slot => slot.started.promise)));
 groups[1].slots[0].release.reject(first);
 expect(await outcome).toBe(first);
 groups[0].slots[0].release.reject(later);
 for (const group of groups.slice(0, 2)) {
  for (const slot of group.slots.slice(0, 10)) slot.release.resolve();
  await Promise.all(group.slots.slice(0, 10).map(slot => slot.finished.promise));
 }
 for (const slot of groups[2].slots) {
  await slot.started.promise;
  slot.release.resolve();
  await slot.finished.promise;
 }
 expect(await outcome).toBe(first);
 for (const [index, group] of groups.entries()) {
  const rows = Array.from({ length: index === 2 ? 12 : 10 }, (_, row) => row);
  expect(group.starts).toStrictEqual(rows);
  expect(group.finishes.toSorted((a, b) => a - b)).toStrictEqual(rows);
  expect(group.cache.reads).toStrictEqual([rawIndex, ...rows.map(row => `api-key:by-id:${group.slots[row].id}`)]);
  expect([...group.cache.values]).toStrictEqual(group.before);
  expect(group.cache.writes).toStrictEqual([]);
 }
 expect(memory).toStrictEqual(stored);
});
