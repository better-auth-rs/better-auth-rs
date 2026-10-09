import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { runWithTransaction } from "@better-auth/core/context";
import { getWithHooks } from "../node_modules/better-auth/dist/db/with-hooks.mjs";

import { base, checkVerificationConsume, consumeModes, date, row, stored } from "./verification-consume-hooks-contract";

for (const mode of consumeModes) {
  test(`SQLite Verification ${mode} consumption returns the post-hook deleted record and preserves transactional failures`, async () => {
    const database = new Database(":memory:");
    try {
      await checkVerificationConsume("sqlite", mode, database, async () => database.query("SELECT * FROM verification ORDER BY id").all());
    } finally { database.close(); }
  });
}

test("Verification single delete catches selector failures while consume and batch delete propagate failures", async () => {
  const database = new Database(":memory:");
  const options = base(database);
  const events: string[] = [];
  const hooks = { verification: { delete: { before() { events.push("before"); }, after() { events.push("after"); } } } };
  try {
    await (await getMigrations(options)).runMigrations();
    const observer = await betterAuth(options).$context;
    const original = { ...row("target", "subject", "original-proof"), expiresAt: date(-1_000_000_000) };
    await observer.adapter.create({ model: "verification", data: original, forceAllowId: true });
    const context = await betterAuth({ ...options, databaseHooks: hooks, verification: { additionalFields: {
      identifier: { type: "string", fieldName: "missing_identifier" },
      expiresAt: { type: "date", fieldName: "missing_expiresAt" },
    } } }).$context;
    const withHooks = getWithHooks(context.adapter, { options: context.options, hooks: [{ source: "user", hooks }] });
    const where = [{ field: "identifier", value: "subject" }];
    expect(await withHooks.deleteWithHooks(where, "verification")).toBeNull();
    expect(await runWithTransaction(context.adapter, () => withHooks.deleteWithHooks(where, "verification"))).toBeNull();
    await expect(context.internalAdapter.consumeVerificationValue("subject")).rejects.toThrow();
    await expect(withHooks.deleteManyWithHooks([{ field: "expiresAt", operator: "lt", value: new Date() }], "verification")).rejects.toThrow();
    expect(events).toStrictEqual([]);
    expect(database.query("SELECT * FROM verification").all()).toStrictEqual([stored("sqlite", original)]);
  } finally { database.close(); }
});
