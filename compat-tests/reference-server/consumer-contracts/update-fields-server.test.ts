import { test } from "bun:test";
import { captureFreshServerCatalog } from "../contracts/server-catalog-shared.mjs";
import { checkUpdateFields } from "../contracts/update-fields-contract";

for (const backend of ["postgres", "mysql"] as const) {
  for (const operation of ["account", "accountMany", "verification", "session"] as const) {
    for (const mode of ["values", "empty", "continue"] as const) {
      test(`${backend} ${operation} ${mode} preserves original update fields and shallow detachment`, async () => {
        await captureFreshServerCatalog(backend, ["account", "session", "user", "verification"], {}, async ({ options, query }) => {
          await checkUpdateFields(backend, operation, mode, options.database, async model => {
            const table = backend === "postgres" ? `"${model}"` : `\`${model}\``;
            return structuredClone(await query(`SELECT * FROM ${table}`));
          });
        });
      });
    }
  }
}
