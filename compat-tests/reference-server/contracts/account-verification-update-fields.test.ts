import { test } from "bun:test";
import { Database } from "bun:sqlite";
import { memoryAdapter } from "better-auth/adapters/memory";
import { checkUpdateFields, type Fields } from "./update-fields-contract";
import "./session-update-secondary-contract";

for (const backend of ["memory", "sqlite"] as const) {
  for (const operation of ["account", "accountMany", "verification", "session"] as const) {
    for (const mode of ["values", "empty", "continue"] as const) {
      test(`${backend} ${operation} ${mode} preserves original update fields and shallow detachment`, async () => {
        const memory: Record<string, Fields[]> = { user: [], session: [], account: [], verification: [] };
        const database = backend === "sqlite" ? new Database(":memory:") : undefined;
        try {
          await checkUpdateFields(backend, operation, mode, database ?? memoryAdapter(memory), async model =>
            structuredClone(database ? database.query(`SELECT * FROM ${model}`).all() as Fields[] : memory[model]));
        } finally { database?.close(); }
      });
    }
  }
}
