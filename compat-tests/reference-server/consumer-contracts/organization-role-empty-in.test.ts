import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { captureFreshServerCatalog } from "../contracts/server-catalog-shared.mjs";

type Backend = "sqlite" | "postgres" | "mysql";

function configuration(events: string[]): BetterAuthOptions {
  return {
    baseURL: "http://organization-role-empty-in.test",
    secret: "organization-role-empty-in-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [organization({ dynamicAccessControl: { enabled: true } }), {
      id: "organization-role-empty-in", schema: { organizationRole: { fields: {
        role: { type: "string", transform: {
          input(value) { events.push("role-input"); return value; },
          output(value) { events.push("role-output"); return value; },
        } },
      } } },
    }],
  };
}

async function check(
  backend: Backend,
  options: BetterAuthOptions,
  events: string[],
  raw: () => Promise<unknown[]>,
) {
  const { adapter } = await betterAuth(options).$context;
  const createdAt = new Date("2030-01-01T00:00:00.000Z");
  for (const [id, organizationId, role] of [
    ["target", "target-org", "reader"],
    ["unrelated", "other-org", "writer"],
  ]) {
    await adapter.create({ model: "organization", forceAllowId: true, data: {
      id: organizationId, name: organizationId, slug: organizationId, createdAt,
    } });
    await adapter.create({ model: "organizationRole", forceAllowId: true, data: {
      id, organizationId, role, permission: "{}", createdAt, updatedAt: null,
    } });
  }
  const before = await raw();
  expect(before).toHaveLength(2);
  events.length = 0;
  const query = () => adapter.findMany({ model: "organizationRole", where: [
    { field: "organizationId", value: "target-org" },
    { field: "role", operator: "in", value: [] },
  ] });
  if (backend === "sqlite") {
    expect(await query()).toStrictEqual([]);
  } else {
    let failure: unknown;
    try { await query(); } catch (error) { failure = error; }
    if (!(failure instanceof Error)) throw new Error("Empty OrganizationRole IN must fail with a database syntax error");
    if (backend === "postgres") {
      expect({ name: failure.name, message: failure.message }).toStrictEqual({
        name: "error", message: 'syntax error at or near ")"',
      });
    } else {
      expect(failure.name).toBe("Error");
      // SQLx prepares placeholders; mysql2 interpolates values in the SQL fragment.
      expect(failure.message).toMatch(/^You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '\)[\s\S]*' at line 1$/);
    }
  }
  expect(events).toStrictEqual([]);
  expect(await raw()).toStrictEqual(before);
}

test("sqlite OrganizationRole empty IN returns no rows and preserves storage", async () => {
  const database = new Database(":memory:");
  try {
    const events: string[] = [];
    const options = { ...configuration(events), database };
    await (await getMigrations(options)).runMigrations();
    await check("sqlite", options, events, async () =>
      structuredClone(database.query("SELECT * FROM organizationRole ORDER BY id").all()));
  } finally {
    database.close();
  }
});

for (const backend of ["postgres", "mysql"] as const) {
  test(`${backend} OrganizationRole empty IN retains the syntax error and preserves storage`, async () => {
    const events: string[] = [];
    await captureFreshServerCatalog(backend, ["organizationRole"], configuration(events), async ({ options, query }) => {
      const table = backend === "postgres" ? '"organizationRole"' : "`organizationRole`";
      await check(backend, options, events, async () =>
        structuredClone(await query(`SELECT * FROM ${table} ORDER BY id`)));
    });
  });
}
