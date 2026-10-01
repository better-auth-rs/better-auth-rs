import {endpoints,modes,runCase} from "./api-key-metadata";
const raw=[];
for(const endpoint of endpoints)for(const backend of ["database","fallback","cache"])for(const [scheduling,result]of modes)raw.push(await runCase(endpoint,backend,scheduling,result));
await Bun.write(process.argv[2],JSON.stringify(raw.map(value=>({endpoint:value.endpoint,backend:value.backend,scheduling:value.scheduling,result:value.result,metadata:value.metadata,before:value.storedBeforeRelease,after:value.storedAfterResponse,taskStates:value.taskStates,migrationWarnings:value.logs.filter(log=>log.message==="migration-warning").length,handlerWarnings:value.logs.filter(log=>log.message==="Failed to run background task:").length})),null,2)+"\n");
await Bun.write(process.argv[3],JSON.stringify(raw,null,2)+"\n");
