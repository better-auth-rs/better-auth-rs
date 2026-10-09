import { expect } from "bun:test";
import { Database } from "bun:sqlite";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
export { date, generator, withoutId } from "./account-id-input-support";
import { date, idSentinel as accountIdSentinel, type Backend, type Fields } from "./account-id-input-support";

export type { Backend, Fields };
export type Model = "organization" | "member" | "invitation" | "team" | "organizationRole";
export type Entry = { model: Model; operation: "create" | "insert" };
export type Policies = Record<string, DBFieldAttribute>;
export type GenerateId = NonNullable<NonNullable<BetterAuthOptions["advanced"]>["database"]>["generateId"];
export const idSentinel = () => ({ ...accountIdSentinel(), defaultValue: "ignored-default" });
export const models: Model[] = ["organization", "member", "invitation", "team", "organizationRole"];
export const entries: Entry[] = [
  ...models.map(model => ({ model, operation: "create" as const })),
  { model: "organization", operation: "insert" }, { model: "member", operation: "insert" },
];
export const probeColumn = (model: Model) => model === "organization" || model === "team" ? "name" : "role";

export function row(model: Model, id: unknown, label = "target"): Fields {
  switch (model) {
    case "organization": return { id, name: label, slug: label, logo: null, createdAt: date(0), metadata: "{}" };
    case "member": return { id, organizationId: "parent", userId: "owner", role: label, createdAt: date(0) };
    case "invitation": return {
      id, organizationId: "parent", email: `${label}@organization-id-input.test`, role: label,
      status: "pending", teamId: null, expiresAt: date(10), createdAt: date(0), inviterId: "owner",
    };
    case "team": return { id, name: label, memberCount: 0, organizationId: "parent", createdAt: date(0), updatedAt: null };
    case "organizationRole": return { id, organizationId: "parent", role: label, permission: "{}", createdAt: date(0), updatedAt: null };
  }
}

export function referencesAsStrings(model: Model): Policies {
  return Object.fromEntries(({
    organization: [], member: ["organizationId", "userId"], invitation: ["organizationId", "inviterId"],
    team: ["organizationId"], organizationRole: ["organizationId"],
  }[model]).map(field => [field, { type: "string" }]));
}

export async function created(model: Model, operation: () => Promise<unknown>, expected: Fields | null) {
  if (expected) expect(await operation()).toStrictEqual(expected);
  else {
    let caught: unknown;
    try { await operation(); } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(Error);
    const error = caught as Error & { code?: string; errno?: number };
    expect({ name: error.name, message: error.message, code: error.code, errno: error.errno }).toStrictEqual({
      name: "SQLiteError", message: `NOT NULL constraint failed: ${model}.id`,
      code: "SQLITE_CONSTRAINT_NOTNULL", errno: 1299,
    });
  }
}

export async function setup(backend: Backend, model: Model) {
  const memory: Record<string, Fields[]> = Object.fromEntries([
    "user", "session", "account", "verification", ...models, "teamMember",
  ].map(model => [model, []]));
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const plugin = (fields: Policies = {}) => organization({
    teams: { enabled: true }, dynamicAccessControl: { enabled: true },
    schema: { [model]: { additionalFields: fields } },
  });
  const options: BetterAuthOptions = {
    database: sqlite ?? memoryAdapter(memory), baseURL: "http://organization-id-input.test",
    secret: "organization-id-input-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, plugins: [plugin()],
  };
  if (sqlite) await (await getMigrations(options)).runMigrations();
  const writer = (await betterAuth(options).$context).adapter;
  await writer.create({ model: "user", forceAllowId: true, data: {
    id: "owner", name: "Owner", email: "owner@organization-id-input.test", emailVerified: true,
    image: null, createdAt: date(0), updatedAt: date(0),
  } });
  if (model !== "organization") await writer.create({
    model: "organization", forceAllowId: true, data: row("organization", "parent", "parent"),
  });
  const seed = (data: Fields) => writer.create({ model, forceAllowId: true, data });
  await seed(row(model, "retained", "retained"));
  return {
    seed,
    async reader(fields: Policies = {}, generateId?: GenerateId) {
      return (await betterAuth({
        ...options, advanced: { database: { generateId } }, plugins: [plugin(fields)],
      }).$context).adapter;
    },
    storage: () => sqlite ? sqlite.query(`SELECT * FROM ${model} ORDER BY rowid`).all() : memory[model],
    stored: (fields: Fields) => sqlite ? Object.fromEntries(Object.entries(fields).map(([key, value]) => [
      key, value instanceof Date ? value.toISOString() : key === "id" && typeof value === "number" ? String(value) : value,
    ])) : fields,
    close: () => sqlite?.close(),
  };
}
