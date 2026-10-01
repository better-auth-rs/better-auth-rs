import {test,expect} from "bun:test";
import {modes,runCase} from "./rate-cleanup-notifications";
for(const [scheduling,result]of modes)test(`rate cleanup ${scheduling}/${result}`,async()=>{
 const value=await runCase(scheduling,result);const sync=result==="sync-throw";
 expect(value.respondedBeforeRelease).toBe(scheduling!=="default");
 expect(value.storedBeforeRelease).toEqual({rows:2,reset:1});
 expect(value.storedAfterResponse).toEqual({rows:result==="resolve"?1:2,reset:1});
 expect(value.status).toEqual(sync?{status:null,thrown:"cleanup-sync"}:{status:200,thrown:null});
 const expected=[];if(scheduling==="handler-throw"&&!sync)expected.push({message:"Failed to run background task:",error:"handler-sync"});if(result!=="resolve"&&!sync)expected.push({message:"Error pruning rate limit rows",error:"cleanup-async"});
 expect(value.logs).toEqual(expected);expect(value.taskStates).toEqual(!sync&&scheduling!=="default"?["fulfilled"]:[]);
 if(result==="immediate-reject"){expect(value.events.indexOf("handler")).toBeLessThan(value.events.indexOf("log:cleanup-async"));expect(value.events.indexOf("log:cleanup-async")).toBeLessThan(value.events.indexOf("response"));}
});
