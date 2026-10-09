import { test } from "bun:test";
import { captureFreshServerCatalog } from "../contracts/server-catalog-shared.mjs";
import { checkVerificationConsume, consumeModes } from "../contracts/verification-consume-hooks-contract";

for (const backend of ["postgres", "mysql"] as const) {
  for (const mode of consumeModes) {
    test(`${backend} Verification ${mode} consumption preserves deleted results and hook failures`, async () => {
      await captureFreshServerCatalog(backend, ["account", "session", "user", "verification"], {}, async ({ options, query }) => {
        await checkVerificationConsume(backend, mode, options.database, async () => {
          const table = backend === "postgres" ? '"verification"' : "`verification`";
          return structuredClone(await query(`SELECT * FROM ${table} ORDER BY id`));
        });
      });
    });
  }
}
