import {modes,runCase} from "./rate-cleanup-notifications";
for(const [scheduling,result]of modes)console.log(JSON.stringify(await runCase(scheduling,result)));
