import {runCase, type Endpoint, type Transport, type Scheduling, type Sender} from "./fixture";
const results = [];
for (const endpoint of ["email-otp", "two-factor"] as Endpoint[]) for (const transport of ["http", "native"] as Transport[]) {
  for (const scheduling of ["default", "handler", "handler-throw"] as Scheduling[]) for (const sender of ["resolve", "reject", "sync-throw", "void", "reject-immediate"] as Sender[]) {
    const result = await runCase(endpoint, transport, scheduling, sender);
    results.push(result);
    console.log(JSON.stringify({...result, contexts: result.contexts.length}));
  }
}
console.log(JSON.stringify(results, null, 2));
