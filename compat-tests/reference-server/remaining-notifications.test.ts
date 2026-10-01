import {test,expect} from "bun:test";
import {endpoints,modes,runCase} from "./remaining-notifications";
for(const endpoint of endpoints)for(const transport of ["http","native"] as const)for(const [scheduling,sender]of modes)test(`${endpoint}/${transport}/${scheduling}/${sender}`,async()=>{
  const result=await runCase(endpoint,transport,scheduling,sender);
  const asynchronous=sender==="resolve"||sender==="reject",scheduled=asynchronous&&scheduling!=="default";
  expect(result.respondedBeforeRelease).toBe(!asynchronous||scheduled);
  expect(result.storedBeforeRelease).toEqual({users:1,invitations:endpoint==="signup"?0:1});
  expect(result.storedAfterResponse).toEqual(result.storedBeforeRelease);
  expect(result.outcome).toEqual(sender==="sync-throw"?{status:transport==="http"?500:null,thrown:transport==="native"?"sender-sync":null}:{status:200,thrown:null});
  expect(result.taskStates).toEqual(scheduled?["fulfilled"]:[]);
  const errors=[];if(scheduling==="handler-throw"&&scheduled)errors.push("handler-sync");if(sender==="reject")errors.push("sender-async");
  expect(result.logs).toEqual(errors.map(error=>({message:"Failed to run background task:",error})));
  if(endpoint==="invite")expect(result.events.includes("organization:after")).toBe(sender!=="sync-throw");
  if(endpoint==="resend")expect(result.events).not.toContain("organization:after");
  if(endpoint==="signup"){expect(result.events[0]).toBe("hash");expect(result.events.includes("synthetic")).toBe(sender!=="sync-throw");}
  for(const context of result.contexts)expect(context.request).toBe(transport==="http");
  if(scheduled)expect(result.events.indexOf("response")).toBeLessThan(result.events.indexOf("gate:release"));
});
