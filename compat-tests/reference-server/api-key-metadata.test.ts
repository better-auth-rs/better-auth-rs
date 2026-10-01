import {test,expect} from "bun:test";
import {endpoints,modes,runCase} from "./api-key-metadata";
for(const endpoint of endpoints)for(const backend of ["database","fallback","cache"])for(const [scheduling,result]of modes)test(`${endpoint}/${backend}/${scheduling}/${result}`,async()=>{
 const value=await runCase(endpoint,backend,scheduling,result),migrates=backend!=="cache",scheduled=migrates&&endpoint==="list"&&scheduling!=="default";
 expect(value.respondedBeforeRelease).toBe(!migrates||scheduled);
 expect(value.metadata).toEqual(endpoint==="list"?[{legacy:"one"},{legacy:"two"}]:[{legacy:"one"}]);
 expect(value.storedBeforeRelease.database).toEqual(migrates?[JSON.stringify({legacy:"one"}),JSON.stringify({legacy:"two"})]:[]);
 expect(value.storedAfterResponse.database).toEqual(!migrates?[]:result==="reject"?[JSON.stringify({legacy:"one"}),JSON.stringify({legacy:"two"})]:endpoint==="list"?[{legacy:"one"},{legacy:"two"}]:[{legacy:"one"},JSON.stringify({legacy:"two"})]);
 expect(value.taskStates).toEqual(scheduled?["fulfilled"]:[]);
 expect(value.logs.filter(log=>log.message==="migration-warning")).toHaveLength(migrates&&result==="reject"?(endpoint==="list"?2:1):0);
 expect(value.logs.filter(log=>log.message==="Failed to run background task:")).toHaveLength(scheduled&&scheduling==="handler-throw"?1:0);
});
