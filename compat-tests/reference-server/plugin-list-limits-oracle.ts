import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { Database } from "bun:sqlite";
import { createHmac } from "node:crypto";
const { getJwksAdapter } = await import(new URL("./plugins/jwt/adapter.mjs", import.meta.resolve("better-auth")).href);

const { generateExportedKeyPair } = await import(new URL("./plugins/jwt/index.mjs", import.meta.resolve("better-auth")).href);
const material = await generateExportedKeyPair();

const secret = "plugin-list-limit-secret-at-least-32-characters";
const token = "plugin-list-token";
const cookie = `better-auth.session_token=${encodeURIComponent(`${token}.${createHmac("sha256",secret).update(token).digest("base64")}`)}`;
const results = [];
for (const backend of ["memory", "sqlite"]) {
 for (const limit of [0, 1, 2, 100]) {
  const rows = {user: [], session: [], account: [], verification: [], passkey: [], jwks: []};
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const options = {database: database ?? memoryAdapter(rows),baseURL:"http://lists.test",secret,
   logger:{disabled:true},advanced:{database:{defaultFindManyLimit:limit}},plugins:[passkey(),jwt({jwks:{disablePrivateKeyEncryption:true}})]};
  if(database) await (await getMigrations(options)).runMigrations();
  const auth=betterAuth(options); const context=await auth.$context;
  const user=await context.adapter.create({model:"user",data:{name:"Owner",email:"owner@lists.test",emailVerified:true,createdAt:new Date(),updatedAt:new Date()}});
  await context.adapter.create({model:"session",data:{token,userId:user.id,expiresAt:new Date("2099-01-01"),createdAt:new Date(),updatedAt:new Date()}});
  const names=new Map<string,string>();
  for(const [index,name] of ["first","second","third"].entries()) {
   await context.adapter.create({model:"passkey",data:{userId:user.id,name,publicKey:"fixture-public-key",credentialID:Buffer.from(name).toString("base64url"),counter:0,deviceType:"singleDevice",backedUp:false,createdAt:new Date(2000+index,0,1)}});
   const key=await context.adapter.create({model:"jwks",data:{publicKey:JSON.stringify(material.publicWebKey),privateKey:JSON.stringify(material.privateWebKey),createdAt:new Date(2000+index,0,1),expiresAt:new Date(index===0?"2001-01-01":"2099-01-01"),alg:"EdDSA",crv:"Ed25519"}});
   names.set(key.id,name);
  }
  const passkeys=await auth.api.listPasskeys({headers:new Headers({cookie})});
  const adapter=getJwksAdapter(context.adapter,{});
  const keys=await adapter.getAllKeys();
  const signed=await auth.api.signJWT({body:{payload:{sub:"fixture"}}});
  const header=JSON.parse(Buffer.from(signed.token.split(".")[0],"base64url").toString());
  results.push({backend,limit,passkeys:passkeys.map((value:any)=>value.name),keys:keys.map((value:any)=>names.get(value.id)),selected:names.get(header.kid)??"generated"});
  database?.close();
 }
}
await Bun.write(process.argv[2]??"/dev/stdout",JSON.stringify(results,null,2)+"\n");
