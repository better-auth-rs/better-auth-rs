import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

test("plugin-declared ordinary passkey names transform once around Memory and SQLite writes", async () => {
  for (const backend of ["memory", "sqlite"] as const) {
    const trace: string[] = [];
    const inputError = new Error("ordinary input error");
    const outputError = new Error("ordinary output error");
    const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], passkey: [] };
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const options = {
      database: database ?? memoryAdapter(memory),
      baseURL: "http://fields.test", secret: "ordinary-model-fields-secret-at-least-32-characters",
      logger: { disabled: true },
      plugins: [passkey(), { id: "ordinary-model-fields", schema: { passkey: { fields: {
        name: { type: "string" as const, onUpdate: () => "Renewed", transform: {
          input(value: any) {
            trace.push(`input:${JSON.stringify(value)}`);
            if (value === "input-error") throw inputError;
            return value.trim();
          },
          output(value: any) {
            trace.push(`output:${JSON.stringify(value)}`);
            if (value === "output-error") throw outputError;
            return `${value}:out`;
          },
        } },
      } } } }],
    };
    if (database) await (await getMigrations(options)).runMigrations();
    const { adapter } = await betterAuth(options).$context;
    const user: any = await adapter.create({ model: "user", data: {
      name: "Owner", email: "ordinary@fields.test", emailVerified: false,
      createdAt: new Date(), updatedAt: new Date(),
    } });
    const create = (name: string) => adapter.create<any>({ model: "passkey", data: {
      name, userId: user.id, credentialID: `credential:${name}`, publicKey: "ordinary-public-key",
      counter: 0, deviceType: "singleDevice", backedUp: false, createdAt: new Date(),
    } });
    const rawNames = () => (database
      ? database.query<{ name: string }, []>('SELECT name FROM "passkey"').all()
      : memory.passkey).map(row => row.name).sort();
    const created = await create("  Desk  ");
    expect(created.name).toBe("Desk:out");
    expect(trace).toStrictEqual(['input:"  Desk  "', 'output:"Desk"']);
    expect(rawNames()).toStrictEqual(["Desk"]);
    const where = [{ field: "id", value: created.id }];
    const updated: any = await adapter.update({ model: "passkey", where, update: { name: "  Mobile  " } });
    expect(updated.name).toBe("Mobile:out");
    expect((await adapter.findOne<any>({ model: "passkey", where }))?.name).toBe("Mobile:out");
    const renewed: any = await adapter.update({ model: "passkey", where, update: { counter: 0 } });
    expect(renewed.name).toBe("Renewed:out");
    await create(" Travel ");
    trace.length = 0;
    const listed: any[] = await adapter.findMany({ model: "passkey" });
    expect(trace).toStrictEqual(listed.map(row => `output:${JSON.stringify(row.name.slice(0, -4))}`));
    expect(listed.map(row => row.name).sort()).toStrictEqual(["Renewed:out", "Travel:out"]);
    expect(rawNames()).toStrictEqual(["Renewed", "Travel"]);
    await expect(create("input-error")).rejects.toBe(inputError);
    expect(rawNames()).toStrictEqual(["Renewed", "Travel"]);
    await expect(create("output-error")).rejects.toBe(outputError);
    expect(rawNames()).toStrictEqual(["Renewed", "Travel", "output-error"]);
    database?.close();
  }
});
