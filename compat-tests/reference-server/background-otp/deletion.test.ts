import { afterAll, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { runWithTransaction } from "@better-auth/core/context";

const traces: unknown[] = [];
for (const outcome of ["commit", "rollback", "after-error"] as const) {
  test(`delete transaction/${outcome}`, async () => {
    const database = new Database(":memory:");
    const events: string[] = [];
    const options: any = {database, baseURL: "http://localhost:3000", secret: "background-transaction-delete-secret-at-least-thirty-two-characters", logger: {disabled: true},
      databaseHooks: {verification: {delete: {
        before: () => {events.push("before");},
        after: () => {events.push("after"); if(outcome === "after-error") throw new Error("after-error");},
      }}}};
    await (await getMigrations(options)).runMigrations();
    const ctx = await betterAuth(options).$context;
    await ctx.internalAdapter.createVerificationValue({identifier: "transaction-delete", value: "123456:0", expiresAt: new Date("2099-01-01T00:00:00Z")});
    let error: string | null = null;
    let foundInside: boolean | undefined;
    try {
      await runWithTransaction(ctx.adapter, async () => {
        await ctx.internalAdapter.deleteVerificationByIdentifier("transaction-delete");
        foundInside = !!(await ctx.internalAdapter.findVerificationValue("transaction-delete"));
        events.push("after-delete");
        if(outcome === "rollback") throw new Error("rollback");
      });
    } catch (failure: any) {error = failure.message;}
    const count = (database.query("select count(*) as count from verification").get() as any).count;
    const actual = {outcome, foundInside, error, events, count};
    traces.push(actual);
    expect(actual).toEqual({outcome, foundInside: false, error: outcome === "commit" ? null : outcome,
      events: ["before", "after-delete", ...(outcome === "rollback" ? [] : ["after"])], count: outcome === "rollback" ? 1 : 0});
    database.close();
  });
}
afterAll(async () => { if (process.env.BACKGROUND_OTP_RESULTS) await Bun.write(`${process.env.BACKGROUND_OTP_RESULTS}/deletion-results.json`, JSON.stringify(traces, null, 2)); });
