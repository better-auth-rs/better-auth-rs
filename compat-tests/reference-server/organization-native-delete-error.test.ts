import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { getOrgAdapter } from "./node_modules/better-auth/dist/plugins/organization/adapter.mjs";

for (const backend of ["memory", "sqlite"]) {
  for (const explicitSubject of [false, true]) {
    test(`${backend}/delete projection failure/${explicitSubject}`, async () => {
      let reject = false;
      const pluginOptions: any = {
        teams: { enabled: true },
        schema: { team: { additionalFields: { name: { type: "string", transform: { output: (value: any) => {
          if (reject) throw new Error("team projection rejected");
          return value;
        } } } } } },
      };
      const db = backend === "sqlite" ? new Database(":memory:") : undefined;
      const options: any = {
        baseURL: "http://localhost:3000", secret: "organization-native-fixture-secret-long-enough",
        database: db, logger: { disabled: true }, plugins: [organization(pluginOptions)],
      };
      if (db) await (await getMigrations(options)).runMigrations();
      const context = await betterAuth(options).$context;
      const data = { createdAt: new Date() };
      await context.adapter.create({ model: "user", forceAllowId: true, data: { ...data, id: "owner", name: "Owner", email: "owner@example.com", emailVerified: true, updatedAt: new Date() } });
      await context.adapter.create({ model: "organization", forceAllowId: true, data: { ...data, id: "org", name: "Org", slug: "org" } });
      await context.adapter.create({ model: "member", forceAllowId: true, data: { ...data, id: "member", organizationId: "org", userId: "owner", role: "owner" } });
      await context.adapter.create({ model: "team", forceAllowId: true, data: { ...data, id: "team", organizationId: "org", name: "Team" } });
      await context.adapter.create({ model: "teamMember", data: { ...data, teamId: "team", userId: "owner" } });
      reject = true;
      await expect(getOrgAdapter(context, pluginOptions).deleteMember({ memberId: "member", organizationId: "org", ...(explicitSubject ? { userId: "owner" } : {}) })).rejects.toThrow("team projection rejected");
      reject = false;
      expect(await context.adapter.count({ model: "member" })).toBe(1);
      expect(await context.adapter.count({ model: "teamMember" })).toBe(1);
      db?.close();
    });
  }
}
