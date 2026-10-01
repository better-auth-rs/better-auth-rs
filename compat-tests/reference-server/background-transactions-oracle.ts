import { transactionCase } from "./background-transactions";

const results = [];
for (const backend of ["sqlite", "memory"] as const)
  for (const transport of ["http", "native"] as const)
    for (const scheduled of [false, true])
      for (const outcome of ["commit", "rollback", "after-hook-error"] as const)
        results.push(await transactionCase(transport, scheduled, outcome, backend));
console.log(JSON.stringify(results, null, 2));
