import { getAuthTables } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import { getMigrations } from "better-auth/db/migration";
import configurations from "../../schema-consumer/verification-catalog-config.json";
import { observeSqliteCatalog } from "./sqlite-catalog";

export async function captureVerificationCatalog() {
  const cases = [];
  for (const [name, configuration] of Object.entries(configurations)) {
    const database = new Database(":memory:");
    const options = {
      ...configuration,
      baseURL: "http://verification-catalog.test",
      secret: "ordinary-verification-catalog-secret-at-least-32-characters",
      database,
      telemetry: { enabled: false },
    };
    try {
      await (await getMigrations(options)).runMigrations();
      const tableName = getAuthTables(options).verification.modelName;
      const { catalog, ddl } = observeSqliteCatalog(
        database,
        tableName,
        "The generated Verification table exists in the SQLite catalog",
      );
      console.error(JSON.stringify({ case: name, ddl }));
      cases.push({ name, ...catalog });
    } finally {
      database.close();
    }
  }
  return {
    version: (await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json()).version,
    database: "sqlite",
    cases,
  };
}

if (import.meta.main) console.log(JSON.stringify(await captureVerificationCatalog(), null, 2));
