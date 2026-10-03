import { getAuthTables } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import type { BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import configurations from "../../schema-consumer/team-catalog-config.json";
import { observeSqliteCatalog } from "./sqlite-catalog";

export async function captureTeamCatalog() {
  const cases = [];
  for (const [name, configuration] of Object.entries(configurations)) {
    const database = new Database(":memory:");
    try {
      const options: BetterAuthOptions = {
        baseURL: "http://team-catalog.test",
        secret: "ordinary-team-catalog-secret-at-least-32-characters",
        database,
        telemetry: { enabled: false },
        plugins: [organization({
          teams: { enabled: true },
          schema: {
            ...("organization" in configuration ? { organization: configuration.organization } : {}),
            ...("team" in configuration ? { team: configuration.team } : {}),
          },
        })],
      };
      await (await getMigrations(options)).runMigrations();
      const schema = getAuthTables(options);
      const { catalog, ddl } = observeSqliteCatalog(
        database,
        schema.team.modelName,
        "The generated team table exists in the SQLite catalog",
      );
      console.error(JSON.stringify({ case: name, model: "team", ddl }));
      cases.push({ name, models: [{ model: "team", ...catalog }] });
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

if (import.meta.main) console.log(JSON.stringify(await captureTeamCatalog(), null, 2));
