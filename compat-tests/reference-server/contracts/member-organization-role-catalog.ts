import { getAuthTables } from "@better-auth/core/db";
import { Database } from "bun:sqlite";
import type { BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import configurations from "../../schema-consumer/member-organization-role-catalog-config.json";
import { observeSqliteCatalog } from "./sqlite-catalog";

export async function captureMemberOrganizationRoleCatalog() {
  const cases = [];
  for (const [name, configuration] of Object.entries(configurations)) {
    const database = new Database(":memory:");
    try {
      const options: BetterAuthOptions = {
        baseURL: "http://member-organization-role-catalog.test",
        secret: "ordinary-member-organization-role-catalog-secret-at-least-32-characters",
        database,
        telemetry: { enabled: false },
        ...("user" in configuration ? { user: configuration.user } : {}),
        plugins: [organization({
          dynamicAccessControl: { enabled: true },
          schema: {
            ...("organization" in configuration ? { organization: configuration.organization } : {}),
            ...("member" in configuration ? { member: configuration.member } : {}),
            ...("organizationRole" in configuration ? { organizationRole: configuration.organizationRole } : {}),
          },
        })],
      };
      await (await getMigrations(options)).runMigrations();
      const schema = getAuthTables(options);
      const models = [];
      for (const model of ["member", "organizationRole"] as const) {
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

if (import.meta.main) console.log(JSON.stringify(await captureMemberOrganizationRoleCatalog(), null, 2));
