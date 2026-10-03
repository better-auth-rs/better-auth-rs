import { getAuthTables } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import type { BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import configurations from "../../schema-consumer/session-catalog-config.json";
import { observeSqliteCatalog } from "./sqlite-catalog";

export async function captureSessionCatalog() {
  const cases = [];
  for (const [name, configuration] of Object.entries(configurations)) {
    const database = new Database(":memory:");
    try {
      const options: BetterAuthOptions = {
        baseURL: "http://session-catalog.test",
        secret: "ordinary-session-catalog-secret-at-least-32-characters",
        database,
        telemetry: { enabled: false },
        ...("user" in configuration ? { user: configuration.user } : {}),
        ...("session" in configuration ? { session: configuration.session } : {}),
      };
      await (await getMigrations(options)).runMigrations();
      const schema = getAuthTables(options);
      const models = [];
      for (const model of ["session"] as const) {
        const { catalog, ddl } = observeSqliteCatalog(
          database,
          schema[model].modelName,
          `The generated ${model} table exists in the SQLite catalog`,
        );
        console.error(JSON.stringify({ case: name, model, ddl }));
        models.push({ model, ...catalog });
      }
      cases.push({ name, models });
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

if (import.meta.main) console.log(JSON.stringify(await captureSessionCatalog(), null, 2));
