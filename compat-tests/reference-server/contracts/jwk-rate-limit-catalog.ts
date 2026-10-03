import { getAuthTables } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import type { BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import configurations from "../../schema-consumer/jwk-rate-limit-catalog-config.json";
import { observeSqliteCatalog } from "./sqlite-catalog";

export async function captureJwkRateLimitCatalog() {
  const cases = [];
  for (const [name, configuration] of Object.entries(configurations)) {
    const database = new Database(":memory:");
    try {
      const jwks = "jwks" in configuration ? configuration.jwks : undefined;
      const options: BetterAuthOptions = {
        baseURL: "http://jwk-rate-limit-catalog.test",
        secret: "ordinary-jwk-rate-limit-catalog-secret-at-least-32-characters",
        database,
        telemetry: { enabled: false },
        plugins: [jwks === undefined ? jwt() : jwt({ schema: { jwks } })],
        rateLimit: {
          storage: "database",
          ...("rateLimit" in configuration ? configuration.rateLimit : {}),
        },
      };
      await (await getMigrations(options)).runMigrations();
      const schema = getAuthTables(options);
      const models = [];
      for (const model of ["jwks", "rateLimit"] as const) {
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

if (import.meta.main) console.log(JSON.stringify(await captureJwkRateLimitCatalog(), null, 2));
