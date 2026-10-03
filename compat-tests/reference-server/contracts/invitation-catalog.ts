import { getAuthTables } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import type { BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import configurations from "../../schema-consumer/invitation-catalog-config.json";
import { observeSqliteCatalog } from "./sqlite-catalog";

export async function captureInvitationCatalog() {
  const cases = [];
  for (const [name, configuration] of Object.entries(configurations)) {
    const database = new Database(":memory:");
    try {
      const options: BetterAuthOptions = {
        baseURL: "http://invitation-catalog.test",
        secret: "ordinary-invitation-catalog-secret-at-least-32-characters",
        database,
        telemetry: { enabled: false },
        ...("user" in configuration ? { user: configuration.user } : {}),
        plugins: [organization({
          teams: { enabled: true },
          schema: {
            ...("organization" in configuration ? { organization: configuration.organization } : {}),
            ...("invitation" in configuration ? { invitation: configuration.invitation } : {}),
          },
        })],
      };
      await (await getMigrations(options)).runMigrations();
      const schema = getAuthTables(options);
      const { catalog, ddl } = observeSqliteCatalog(
        database,
        schema.invitation.modelName,
        "The generated invitation table exists in the SQLite catalog",
      );
      console.error(JSON.stringify({ case: name, model: "invitation", ddl }));
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

if (import.meta.main) console.log(JSON.stringify(await captureInvitationCatalog(), null, 2));
