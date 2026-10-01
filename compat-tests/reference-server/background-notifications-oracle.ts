import {runCase} from "./background-notifications";
const results=[];
for(const endpoint of ["reset","phone"] as const)
for(const transport of ["http","native"] as const)
for(const scheduling of ["default","handler","handler-throw"] as const)
for(const sender of ["resolve","reject","sync-throw","void"] as const)
results.push(await runCase(endpoint,transport,scheduling,sender));
console.log(JSON.stringify(results,null,2));
