import {betterAuth} from 'better-auth';
import {admin,organization,multiSession,magicLink,jwt,deviceAuthorization} from 'better-auth/plugins';
import {createAuthMiddleware} from 'better-auth/api';

// Better Auth 1.7.6: better-call/dist/validator.mjs validates body, query, then requireHeaders.
const auth=betterAuth({baseURL:'http://headers.test',secret:'headers-oracle-secret-at-least-32-characters',logger:{disabled:true},rateLimit:{enabled:false},
 plugins:[admin(),organization({teams:{enabled:true},dynamicAccessControl:{enabled:true}}),multiSession(),magicLink({sendMagicLink:async()=>{}}),jwt(),deviceAuthorization()],
});
function sample(schema:any):any {
 const def=schema.def;
 switch(def.type){
  case 'optional': case 'default': return undefined;
  case 'nullable': return null;
  case 'string': return 'fixture@example.test';
  case 'number': return 1;
  case 'boolean': return true;
  case 'enum': return Object.values(def.entries)[0];
  case 'record': return {};
  case 'array': return [];
  case 'object': return Object.fromEntries(Object.entries(def.shape).map(([key,value])=>[key,sample(value)]).filter(([,value])=>value!==undefined));
  case 'union': return sample(def.options[0]);
  case 'intersection': return {...sample(def.left),...sample(def.right)};
  case 'pipe': return sample(def.in);
  default: throw new Error(`No sample for ${def.type}`);
 }
}
const records=[];
for(const [key,endpoint] of Object.entries(auth.api) as any){
 if(!endpoint.options.requireHeaders)continue;
 const body=endpoint.options.body?sample(endpoint.options.body):undefined;
 const query=endpoint.options.query?sample(endpoint.options.query):undefined;
 if(endpoint.options.body&&!endpoint.options.body.safeParse(body).success)throw new Error(`Invalid body sample: ${key} ${JSON.stringify(body)}`);
 if(endpoint.options.query&&!endpoint.options.query.safeParse(query).success)throw new Error(`Invalid query sample: ${key} ${JSON.stringify(query)}`);
 const variants=[{kind:'missing'},{kind:'request',request:new Request('http://headers.test/source')},{kind:'empty',headers:{}}];
 if(endpoint.options.body)variants.push({kind:'invalid-body',body:7} as any);
 if(endpoint.options.query)variants.push({kind:'invalid-query',query:7} as any);
 for(const variant of variants){
  const input={body,query,...variant};
  const response=await endpoint({...input,asResponse:true});
  const text=await response.text();
  const result=text?JSON.parse(text):null;
  if(['missing','request'].includes(variant.kind)&&JSON.stringify(result)!==JSON.stringify({message:'Headers is required',code:'VALIDATION_ERROR'}))throw new Error(`${key}/${variant.kind}: ${response.status} ${text}`);
  records.push({key,path:endpoint.path,method:Array.isArray(endpoint.options.method)?endpoint.options.method[0]:endpoint.options.method,kind:variant.kind,...(input.body===undefined?{}:{body:input.body}),...(input.query===undefined?{}:{query:input.query}),status:response.status,result});
 }
}
const trace:any[]=[];
const hooks={before:createAuthMiddleware(async(ctx:any)=>{trace.push({phase:'before',query:ctx.query??null,body:ctx.body??null,request:!!ctx.request});}),after:createAuthMiddleware(async(ctx:any)=>{trace.push({phase:'after',query:ctx.query??null,body:ctx.body??null,request:!!ctx.request});})};
const observed=betterAuth({baseURL:'http://headers.test',secret:'headers-oracle-secret-at-least-32-characters',logger:{disabled:true},hooks});
const response=await observed.api.revokeSession({body:{token:'fixture',unknown:7},asResponse:true} as any);
if(response.status!==400||trace.length!==2)throw new Error('Missing headers must retain both hook phases');
const output={records,trace};
await Bun.write(process.argv[2]??'/private/tmp/better-auth-required-headers-upstream.json',JSON.stringify(output,null,2)+'\n');
console.log(`${records.length} endpoint cases and hook ordering passed.`);
