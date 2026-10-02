import { Database } from "bun:sqlite";
const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { getMigrations } = await import(`${modules}/better-auth/dist/db/get-migration.mjs`);

export async function capture(backend: string) {
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events: unknown[] = [];
  let enabled = false;
  let sequence = 0;
  const field = (name: string) => ({type:"string", required:false, transform:{output(value: unknown) {
    if (!enabled) return value;
    events.push([name,value]);
    return `${value}:${++sequence}`;
  }}});
  const options = {database, secret:"ordinary-account-join-at-least-thirty-two-characters", baseURL:"http://ordinary-owner.test", telemetry:{enabled:false}, logger:{disabled:true},
    user:{additionalFields:{name:field("name"),image:field("image")}},
    account:{additionalFields:{accessToken:field("accessToken"),refreshToken:field("refreshToken")}}};
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const {adapter} = await betterAuth(options).$context;
    const createdAt = new Date("2025-01-01T00:00:00Z");
    for (const label of ["A","B"]) {
      const user = await adapter.create({model:"user", data:{name:label,image:`${label}-image`,email:`${label}@ordinary-owner.test`,emailVerified:true,createdAt,updatedAt:createdAt}});
      await adapter.create({model:"account", data:{userId:user.id,accountId:`ordinary-${label}`,providerId:"ordinary",accessToken:`${label}-access`,refreshToken:`${label}-refresh`,createdAt,updatedAt:createdAt}});
    }
    enabled = true;
    const records = await adapter.findMany({model:"account",sortBy:{field:"accountId",direction:"asc"},join:{user:true}});
    return {backend, events, rows:records.map((row:any)=>({accessToken:row.accessToken,refreshToken:row.refreshToken,name:row.user.name,image:row.user.image}))};
  } finally {database?.close();}
}
if (import.meta.main) console.log(JSON.stringify(await Promise.all([capture("memory"),capture("sqlite")]),null,2));
