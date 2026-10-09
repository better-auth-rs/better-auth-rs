import { expect } from "bun:test";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { getCurrentAdapter } from "@better-auth/core/context";

type Fields = Record<string, unknown>;
type Backend = "sqlite" | "postgres" | "mysql";
export const consumeModes = ["payload", "expire", "before-error", "after-error", "output-error", "cancel", "move-id"] as const;
type Mode = typeof consumeModes[number];
// Keep the fixture dates within the MySQL TIMESTAMP range.
export const date = (offset: number) => new Date(1_893_456_000_000 + offset * 1000);
export const row = (id: string, identifier: string, value: string) => ({ id, identifier, value, createdAt: date(0), updatedAt: date(0), expiresAt: date(100) });
export const stored = (backend: Backend, value: Fields) => backend === "sqlite"
  ? { ...value, createdAt: (value.createdAt as Date).toISOString(), updatedAt: (value.updatedAt as Date).toISOString(), expiresAt: (value.expiresAt as Date).toISOString() }
  : value;
export const base = (database: BetterAuthOptions["database"]): BetterAuthOptions => ({
  database, baseURL: "http://verification-consume.test", secret: "verification-consume-hook-secret-at-least-thirty-two-characters",
  logger: { disabled: true }, telemetry: { enabled: false },
});

export async function checkVerificationConsume(
  backend: Backend,
  mode: Mode,
  database: BetterAuthOptions["database"],
  storage: () => Promise<unknown[]>,
) {
  const events: [string, unknown][] = [];
  let outputCalls = 0;
  let adapter: Awaited<ReturnType<typeof betterAuth>["$context"]>["adapter"];
  const options: BetterAuthOptions = {
    ...base(database),
    verification: { additionalFields: { value: { type: "string", transform: { output(value) {
      outputCalls++;
      if (mode === "output-error" && outputCalls === 3) throw new Error("output-error");
      return value;
    } } } } },
    databaseHooks: { verification: { delete: {
      async before(record) {
        events.push(["before", structuredClone(record)]);
        const tx = await getCurrentAdapter(adapter);
        const updated = await tx.update({ model: "verification", where: [{ field: "identifier", value: "subject" }], update: {
          ...(mode === "move-id" ? { id: "moved" } : {}), value: "updated-proof", expiresAt: date(mode === "expire" ? -1_000_000_000 : 200), updatedAt: date(3),
        } });
        events.push(["write", structuredClone(updated)]);
        if (mode === "before-error") throw new Error("before-error");
        if (mode === "cancel") return false;
      },
      async after(record) {
        events.push(["after", structuredClone(record)]);
        if (mode === "after-error") throw new Error("after-error");
      },
    } } },
  };
  if (backend === "sqlite") await (await getMigrations(options)).runMigrations();
  const context = await betterAuth(options).$context;
  adapter = context.adapter;
  const original = row("target", "subject", "original-proof");
  const unrelated = row("unrelated", "unrelated", "retained-proof");
  expect(await adapter.create({ model: "verification", data: original, forceAllowId: true })).toStrictEqual(original);
  expect(await adapter.create({ model: "verification", data: unrelated, forceAllowId: true })).toStrictEqual(unrelated);
  outputCalls = 0;
  const changed = { ...original, ...(mode === "move-id" ? { id: "moved" } : {}), value: "updated-proof", expiresAt: date(mode === "expire" ? -1_000_000_000 : 200), updatedAt: date(3) };
  if (["before-error", "after-error", "output-error"].includes(mode)) {
    await expect(context.internalAdapter.consumeVerificationValue("subject")).rejects.toThrow(mode);
  } else {
    expect(await context.internalAdapter.consumeVerificationValue("subject")).toStrictEqual(["expire", "cancel", "move-id"].includes(mode) ? null : changed);
  }
  expect(events).toStrictEqual([
    ["before", original], ["write", changed],
    ...(["payload", "expire", "after-error"].includes(mode) ? [["after", changed]] : []),
  ]);
  expect(outputCalls).toBe(["before-error", "cancel", "move-id"].includes(mode) ? 2 : 3);
  const remaining = ["before-error", "output-error"].includes(mode) ? original : ["cancel", "move-id"].includes(mode) ? changed : undefined;
  expect(await storage()).toStrictEqual([
    ...(remaining ? [stored(backend, remaining)] : []), stored(backend, unrelated),
  ]);
}
