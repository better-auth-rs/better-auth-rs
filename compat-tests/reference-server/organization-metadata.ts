import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization, testUtils } from "better-auth/plugins";

export async function runOrganizationMetadata(input: { database: "memory" | "sqlite" }) {
  const database = input.database === "sqlite" ? new Database(":memory:") : undefined;
  const options: any = {
    database,
    baseURL: "https://metadata.example",
    secret: "organization-metadata-secret-at-least-thirty-two-characters",
    logger: { disabled: true },
    rateLimit: { enabled: false },
    plugins: [organization(), testUtils()],
  };
  if (database) await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context: any = await auth.$context;
  const helpers = context.test;
  try {
    const raw = [];
    for (const metadata of [null, "plain", '{"key":"value"}', "null", { key: "value" }]) {
      const draft = helpers.createOrganization({ metadata });
      let saved: any;
      try {
        saved = await helpers.saveOrganization(draft);
      } catch (error) {
        if (!database || typeof metadata !== "object" || metadata === null) throw error;
        const read = await context.adapter.findOne({ model: "organization", where: [{ field: "id", value: draft.id }] });
        raw.push({ draft: draft.metadata, rejected: true, persisted: read !== null });
        continue;
      }
      const read = await context.adapter.findOne({ model: "organization", where: [{ field: "id", value: saved.id }] });
      raw.push({ draft: draft.metadata, saved: saved.metadata, read: read.metadata });
    }
    const user = await helpers.saveUser(helpers.createUser());
    const headers = await helpers.getAuthHeaders({ userId: user.id });
    const created = await auth.api.createOrganization({ headers, body: { name: "Route metadata", slug: "route-metadata", metadata: { nested: { value: 1 } } } });
    const id = created!.id;
    const createdRead = await auth.api.getFullOrganization({ headers, query: { organizationId: id } });
    const updated = await auth.api.updateOrganization({ headers, body: { organizationId: id, data: { metadata: {} } } });
    const updatedRead = await auth.api.getFullOrganization({ headers, query: { organizationId: id } });
    return { raw, route: { created: created!.metadata, createdRead: createdRead!.metadata, updated: updated!.metadata, updatedRead: updatedRead!.metadata } };
  } finally {
    database?.close();
  }
}
