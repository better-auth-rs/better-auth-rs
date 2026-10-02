import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";

export async function organizationPluginFields(backend: "memory" | "sqlite", order: "before" | "after") {
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const events: unknown[] = [];
  const policy = (field: string) => ({
    type: "string" as const,
    transform: {
      input(value: string) { events.push([field, "input", value]); return value.trim(); },
      output(value: string) { events.push([field, "output", value]); return `${value}:custom`; },
    },
  });
  const custom = { id: "ordinary-organization-fields", schema: {
    organization: { fields: {
      name: policy("organization.name"),
      logo: { ...policy("organization.logo"), defaultValue: " Default ", onUpdate: () => " Updated " },
    } },
    team: { fields: { name: policy("team.name") } },
  } };
  const own = organization({ teams: { enabled: true }, schema: {
    organization: { additionalFields: {
      name: { type: "string", required: true, transform: {
        output(value: string) { events.push(["organization.name", "own-output", value]); return `${value}:own`; },
      } },
    } },
  } });
  const options = {
    database, baseURL: "http://organization-fields.test", secret: "ordinary-organization-fields-secret-long-enough",
    telemetry: { enabled: false }, logger: { disabled: true },
    plugins: order === "before" ? [custom, own] : [own, custom],
  };
  try {
    if (database) await (await getMigrations(options)).runMigrations();
    const { adapter } = await betterAuth(options).$context;
    const createdAt = new Date("2025-01-01T00:00:00Z");
    const org: any = await adapter.create({ model: "organization", data: { name: " Acme ", slug: "acme", createdAt } });
    const organizationCreated = { name: org.name, logo: org.logo ?? null };
    const updated: any = await adapter.update({ model: "organization", where: [{field: "id", value: org.id}], update: {name: " Renamed "} });
    const organizationUpdated = { name: updated.name, logo: updated.logo ?? null };
    const team: any = await adapter.create({ model: "team", data: {name: " Team ", organizationId: org.id, createdAt, memberCount: 0} });
    const teamCreated = { name: team.name };
    const teamUpdated: any = await adapter.update({ model: "team", where: [{field: "id", value: team.id}], update: {name: " Next "} });
    const listed: any[] = await adapter.findMany({model: "organization"});
    return { backend, order, organizationCreated, organizationUpdated, teamCreated,
      teamUpdated: {name: teamUpdated.name}, listed: listed.map(row => ({name: row.name, logo: row.logo ?? null})), events };
  } finally { database?.close(); }
}
