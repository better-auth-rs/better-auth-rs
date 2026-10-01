import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const first = "EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4";
const updated = "DD4EC289-E01D-41C9-BB89-70FA845D4BF2";

test("ordinary AAGUID policies preserve complete Passkey patches and schema field order", async () => {
  for (const backend of ["memory", "sqlite"] as const) {
    const trace: string[] = [];
    const inputError = new Error("ordinary AAGUID input error");
    const outputError = new Error("ordinary AAGUID output error");
    let failure = 0;
    const field = (name: "name" | "aaguid") => ({
      type: "string" as const, required: true,
      ...(name === "aaguid" ? {defaultValue: first, onUpdate: () => updated} : {}),
      transform: {
        input(value: string) {
          trace.push(`input:${name}`);
          if (name === "aaguid" && failure === 1) throw inputError;
          return name === "aaguid" ? value.trim().toLowerCase() : value.trim();
        },
        output(value: string) {
          trace.push(`output:${name}:${value}`);
          if (name === "aaguid" && failure === 2) throw outputError;
          return name === "aaguid" ? value.toUpperCase() : `${value}:out`;
        },
      },
    });
    const memory: Record<string, any[]> = {user: [], session: [], account: [], verification: [], passkey: []};
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const options = {
      database: database ?? memoryAdapter(memory), baseURL: "http://aaguid.test",
      secret: "ordinary-aaguid-field-contract-at-least-32-characters", logger: {disabled: true},
      plugins: [passkey(), {id: "ordinary-aaguid", schema: {passkey: {fields: {
        aaguid: field("aaguid"), name: field("name"),
      }}}}],
    };
    if (database) await (await getMigrations(options)).runMigrations();
    const {adapter} = await betterAuth(options).$context;
    const user: any = await adapter.create({model: "user", data: {
      name: "Owner", email: "ordinary@aaguid.test", emailVerified: false,
      createdAt: new Date(), updatedAt: new Date(),
    }});
    const create = (name: string, aaguid: string | null) => adapter.create<any>({model: "passkey", data: {
      name, aaguid, userId: user.id, credentialID: `credential:${name}`, publicKey: "ordinary-public-key",
      counter: 0, deviceType: "singleDevice", backedUp: false, createdAt: new Date(),
    }});
    const raw = (id: string): any => database
      ? database.query<any, [string]>('SELECT name,aaguid,counter FROM passkey WHERE id=?').get(id)
      : memory.passkey.find(row => row.id === id);
    const created = await create(" Desk ", ` ${first} `);
    expect(created.name).toBe("Desk:out"); expect(created.aaguid).toBe(first);
    expect(raw(created.id).aaguid).toBe(first.toLowerCase());
    expect(trace).toStrictEqual(["input:name", "input:aaguid", "output:name:Desk", `output:aaguid:${first.toLowerCase()}`]);
    const defaulted = await create(" Default ", null);
    expect(defaulted.aaguid).toBe(first);
    const where = [{field: "id", value: created.id}];
    trace.length = 0;
    const renamed: any = await adapter.update({model: "passkey", where, update: {name: " Mobile "}});
    expect(renamed.aaguid).toBe(updated);
    expect(trace).toStrictEqual(["input:name", "input:aaguid", "output:name:Mobile", `output:aaguid:${updated.toLowerCase()}`]);
    trace.length = 0;
    const counted: any = await adapter.update({model: "passkey", where, update: {counter: 1}});
    expect(counted.counter).toBe(1); expect(counted.name).toBe("Mobile:out");
    expect(trace).toStrictEqual(["input:aaguid", "output:name:Mobile", `output:aaguid:${updated.toLowerCase()}`]);
    expect((await adapter.findOne<any>({model: "passkey", where}))?.aaguid).toBe(updated);
    trace.length = 0;
    const rows: any[] = await adapter.findMany({model: "passkey"});
    expect(rows.length).toBe(2);
    const expectedNames = rows.map(row => row.id === created.id ? "Mobile" : "Default");
    const expectedAaguids = rows.map(row => row.id === created.id ? updated : first);
    expect(trace).toStrictEqual([
      ...expectedNames.map(name => `output:name:${name}`),
      ...expectedAaguids.map(value => `output:aaguid:${value.toLowerCase()}`),
    ]);
    expect(rows.map(row => row.name)).toStrictEqual(expectedNames.map(name => `${name}:out`));
    expect(rows.map(row => row.aaguid)).toStrictEqual(expectedAaguids);
    failure = 1;
    await expect(adapter.update({model: "passkey", where, update: {name: "Input failure"}})).rejects.toBe(inputError);
    expect(raw(created.id).name).toBe("Mobile"); expect(raw(created.id).counter).toBe(1);
    failure = 2;
    await expect(adapter.update({model: "passkey", where, update: {name: " Output "}})).rejects.toBe(outputError);
    expect(raw(created.id).name).toBe("Output"); expect(raw(created.id).counter).toBe(1);
    expect(raw(created.id).aaguid).toBe(updated.toLowerCase());
    database?.close();
  }
});
