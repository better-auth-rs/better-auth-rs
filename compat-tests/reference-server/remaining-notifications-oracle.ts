import {endpoints,modes,runCase} from "./remaining-notifications";
const results=[];
for(const endpoint of endpoints)for(const transport of ["http","native"] as const)for(const [scheduling,sender]of modes)results.push(await runCase(endpoint,transport,scheduling,sender));
console.log(JSON.stringify(results,null,2));
