import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

const models = ["user", "session", "account", "verification"] as const;
const names = ["reference", "references", "nullable", "boolean", "defaulted"];
const expiresAt = new Date("2100-01-01T00:00:00Z");
const select = (row: Record<string, unknown>) => Object.fromEntries(names.map(name => [name, row[name]]));

export async function captureMemorySerialReferences() {
  const families: Record<string, unknown> = {};
  for (const model of models) {
    const trace: unknown[] = [];
    const ref = { model: "user", field: "id" };
    const fields = {
      reference: { type: "string" as const, fieldName: "storedReference", references: ref, transform: {
        input(value: unknown) { trace.push(["input", value]); return String(value).trim(); },
        output(value: unknown) { trace.push(["output", value]); return value; },
      } },
      references: { type: "string[]" as const, references: ref },
      nullable: { type: "string" as const, required: false, references: ref },
      boolean: { type: "boolean" as const, references: ref },
      defaulted: { type: "string" as const, references: ref, defaultValue: "003", onUpdate: () => "004" },
    };
    const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [] };
    const options = {
      database: memoryAdapter(memory),
      baseURL: "http://serial-reference.test",
      secret: "ordinary-serial-reference-secret-at-least-32-characters",
      logger: { disabled: true },
      advanced: { database: { generateId: "serial" as const } },
      [model]: { additionalFields: fields },
    };
    const { adapter } = await betterAuth(options).$context;
    const data: Record<string, unknown> = {
      reference: " 002 ", references: ["002", null, true], nullable: null, boolean: true,
      ...({
        user: { name: "Example", email: "example@serial-reference.test", emailVerified: false, createdAt: new Date(), updatedAt: new Date() },
        session: { userId: "1", token: "ordinary-session", expiresAt, createdAt: new Date(), updatedAt: new Date() },
        account: { userId: "1", providerId: "example", accountId: "external", createdAt: new Date(), updatedAt: new Date() },
        verification: { identifier: "ordinary", value: "value", expiresAt, createdAt: new Date(), updatedAt: new Date() },
      }[model]),
    };
    const created = await adapter.create<Record<string, unknown>>({ model, data });
    const updated = await adapter.update<Record<string, unknown>>({
      model, where: [{ field: "id", value: created.id as string }], update: { reference: " 005 " },
    });
    if (!updated) throw new Error("Ordinary field update did not return a row");
    families[model] = { created: select(created), updated: select(updated), trace };
  }

  const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [] };
  const { adapter } = await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://serial-reference.test",
    secret: "ordinary-serial-reference-secret-at-least-32-characters", logger: { disabled: true },
    user: { additionalFields: { reference: { type: "string", references: { model: "user", field: "id" } } } },
  }).$context;
  const random = await adapter.create<{ reference: string }>({ model: "user", data: {
    name: "Example", email: "random@serial-reference.test", emailVerified: false,
    createdAt: new Date(), updatedAt: new Date(), reference: "002",
  } });
  return { families, random: random.reference };
}

if (import.meta.main) {
  const destination = process.argv[2];
  if (!destination) throw new Error("Pass the absolute fixture destination path");
  await Bun.write(destination, `${JSON.stringify(await captureMemorySerialReferences(), null, 2)}\n`);
}
