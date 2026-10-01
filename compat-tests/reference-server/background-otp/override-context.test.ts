import { afterAll, expect, test } from "bun:test";
import { overrideContextCase } from "./override-context";

const traces: unknown[] = [];
for (const reuse of [false, true]) for (const outcome of ["commit", "rollback", "after-error"] as const) {
  test(`override ambient context/${reuse}/${outcome}`, async () => {
    const actual = await overrideContextCase(reuse, outcome);
    traces.push(actual);
    for (const context of actual.contexts as any[]) {
      const synthetic = context.phase.startsWith("verification:") || context.phase === "sender";
      const project = (otp: boolean) => ({path: otp ? "/email-otp/send-verification-otp" : "/sign-up/email",
        body: otp ? {email: "override@example.com", type: "email-verification"} : {name: "Override", email: "override@example.com", password: "fixture-password"}, request: false});
      expect(context).toEqual({phase: context.phase,
        ambient: project(synthetic && !context.phase.endsWith(".after")), supplied: project(synthetic)});
    }
    expect(actual.contexts.length).toBe(actual.events.length);
  });
}
afterAll(async () => {if (process.env.BACKGROUND_OTP_RESULTS) await Bun.write(`${process.env.BACKGROUND_OTP_RESULTS}/override-context-results.json`, JSON.stringify(traces, null, 2));});
