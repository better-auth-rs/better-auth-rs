import { afterAll, expect, test } from "bun:test";

const modules = `${import.meta.dir}/../../compat-tests/reference-server/node_modules`;
const { betterAuth } = await import(`${modules}/better-auth/dist/index.mjs`);
const { organization } = await import(`${modules}/better-auth/dist/plugins/organization/index.mjs`);
const { memoryAdapter } = await import(`${modules}/better-auth/dist/adapters/memory-adapter/index.mjs`);
const version = (await Bun.file(`${modules}/better-auth/package.json`).json()).version;
const models = ["organization", "member", "invitation", "team", "organizationRole"] as const;
type Model = typeof models[number];
type Transform = {
  input?: (value: unknown) => Promise<unknown>;
  output?: (value: unknown) => Promise<unknown>;
};
const observations: Record<string, unknown> = { version, backend: "memory", models: {} };

async function fixture(model: Model, transform: Transform) {
  const database: Record<string, any[]> = Object.fromEntries(
    ["user", "session", "account", "verification", ...models, "teamMember"].map(name => [name, []]),
  );
  const { adapter } = await betterAuth({
    database: memoryAdapter(database),
    baseURL: "http://organization-async.test",
    secret: "ordinary-organization-async-secret-at-least-32-characters",
    logger: { disabled: true },
    plugins: [organization({
      teams: { enabled: true },
      dynamicAccessControl: { enabled: true },
      schema: { [model]: { additionalFields: {
        label: { type: "string", required: false, fieldName: "stored_label", transform },
      } } },
    })],
  }).$context;
  const createdAt = new Date("2025-01-01T00:00:00.000Z");
  const user = await adapter.create({ model: "user", data: {
    name: "Fixture User", email: "fixture@organization-async.test", emailVerified: true,
    createdAt, updatedAt: createdAt,
  } });
  const org = model === "organization" ? undefined : await adapter.create({
    model: "organization", data: { name: "Fixture Organization", slug: "fixture", createdAt },
  });
  const data = (() => {
    switch (model) {
      case "organization": return { name: "Organization", slug: "organization", createdAt };
      case "member": return { organizationId: org.id, userId: user.id, role: "member", createdAt };
      case "invitation": return {
        organizationId: org.id, email: "invitee@organization-async.test", role: "member",
        status: "pending", inviterId: user.id, createdAt, expiresAt: new Date("2099-01-01T00:00:00.000Z"),
      };
      case "team": return { name: "Fixture Team", organizationId: org.id, createdAt };
      case "organizationRole": return {
        organizationId: org.id, role: "reviewer", permission: JSON.stringify({ organization: ["update"] }), createdAt,
      };
    }
  })();
  return { adapter, database, data };
}

test("uses pinned Better Auth 1.7.6", () => {
  expect(version).toBe("1.7.6");
});

for (const model of models) {
  test(`${model}: await ordinary input before storage and output before return`, async () => {
    const inputStarted = Promise.withResolvers<void>();
    const inputResult = Promise.withResolvers<unknown>();
    const outputStarted = Promise.withResolvers<void>();
    const outputResult = Promise.withResolvers<unknown>();
    const trace: unknown[] = [];
    const { adapter, database, data } = await fixture(model, {
      async input(value) {
        trace.push(["input", value]);
        inputStarted.resolve();
        return await inputResult.promise;
      },
      async output(value) {
        trace.push(["output", value]);
        outputStarted.resolve();
        return await outputResult.promise;
      },
    });
    const pending = adapter.create({ model, data: { ...data, label: "source" } });
    await inputStarted.promise;
    expect(database[model]).toHaveLength(0);
    inputResult.resolve("stored");
    await outputStarted.promise;
    expect(database[model][0].stored_label).toBe("stored");
    expect(database[model][0]).not.toHaveProperty("label");
    outputResult.resolve("visible");
    const row = await pending;
    expect(row.label).toBe("visible");
    expect(row).not.toHaveProperty("stored_label");
    expect(trace).toStrictEqual([["input", "source"], ["output", "stored"]]);
    (observations.models as Record<string, unknown>)[model] = {
      trace, stored: database[model][0].stored_label, returned: row.label,
    };
  });
}

for (const phase of ["input", "output"] as const) {
  test(`team: ${phase} rejection preserves the write boundary`, async () => {
    const failure = new Error(`${phase} application failure`);
    const trace: unknown[] = [];
    const { adapter, database, data } = await fixture("team", {
      async input(value) {
        trace.push(["input", value]);
        if (phase === "input") throw failure;
        return "stored";
      },
      async output(value) {
        trace.push(["output", value]);
        throw failure;
      },
    });
    await expect(adapter.create({ model: "team", data: { ...data, label: "source" } })).rejects.toBe(failure);
    expect(database.team).toHaveLength(phase === "input" ? 0 : 1);
    if (phase === "output") expect(database.team[0].stored_label).toBe("stored");
    observations[`${phase}Failure`] = { trace, storedRows: database.team.length, stored: database.team[0]?.stored_label ?? null };
  });
}

test("team: both batch output callbacks start and reversed completion retains query order", async () => {
  let armed = false;
  const trace: string[] = [];
  const phases = new Map(["A", "B"].map(value => [value, {
    started: Promise.withResolvers<void>(),
    result: Promise.withResolvers<unknown>(),
    finished: Promise.withResolvers<void>(),
  }]));
  const { adapter, database, data } = await fixture("team", {
    async output(value) {
      if (!armed) return value;
      const phase = phases.get(String(value));
      if (!phase) throw new Error(`Unexpected ordinary batch value ${value}`);
      trace.push(`start:${value}`);
      phase.started.resolve();
      const result = await phase.result.promise;
      trace.push(`finish:${value}`);
      phase.finished.resolve();
      return result;
    },
  });
  for (const name of ["A", "B"]) {
    await adapter.create({ model: "team", data: { ...data, name, label: name } });
  }
  armed = true;
  const pending = adapter.findMany({ model: "team", sortBy: { field: "name", direction: "asc" } });
  const a = phases.get("A")!;
  const b = phases.get("B")!;
  await Promise.all([a.started.promise, b.started.promise]);
  expect(trace).toStrictEqual(["start:A", "start:B"]);
  b.result.resolve("B:visible");
  await b.finished.promise;
  expect(trace).toStrictEqual(["start:A", "start:B", "finish:B"]);
  a.result.resolve("A:visible");
  const rows = await pending;
  expect(rows.map((row: any) => row.label)).toStrictEqual(["A:visible", "B:visible"]);
  expect(rows.map((row: any) => row.name)).toStrictEqual(["A", "B"]);
  expect(trace).toStrictEqual(["start:A", "start:B", "finish:B", "finish:A"]);
  observations.batch = { trace, returned: rows.map((row: any) => ({ name: row.name, label: row.label })), stored: database.team.map(row => row.stored_label) };
});

afterAll(async () => {
  if (!process.env.ORGANIZATION_ASYNC_OUTPUT) return;
  await Bun.write(process.env.ORGANIZATION_ASYNC_OUTPUT, `${JSON.stringify(observations, null, 2)}\n`);
});
