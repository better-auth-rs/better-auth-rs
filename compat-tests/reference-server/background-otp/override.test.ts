import { afterAll, expect, test } from "bun:test";
import { overrideCase } from "./override";

const traces: unknown[] = [];
for (const reuse of [false, true]) for (const outcome of ["commit", "rollback", "after-error"] as const) {
  test(`active override/${reuse}/${outcome}`, async () => {
    const actual = await overrideCase(reuse, outcome);
    traces.push(actual);
    expect(actual.observations).toEqual([{path: "/email-otp/send-verification-otp", body: {email: "override@example.com", type: "email-verification"},
      hasRequest: false, userFound: true, value: reuse ? "123456:0" : "654321:0", otp: reuse ? "123456" : "654321"}]);
    expect(actual.result).toEqual(outcome === "commit" ? {status: 200, thrown: null} : {status: null, thrown: outcome === "rollback" ? "session-rejected" : "after-error"});
    const write = reuse ? "update" : "create";
    expect(actual.events).toEqual([`verification:${write}.before`, "sender", "session:create.before",
      ...(outcome === "rollback" ? [] : ["user:create.after"]),
      ...(outcome === "commit" ? [`verification:${write}.after`, "session:create.after"] : [])]);
    expect(actual.stored).toEqual({users: outcome === "rollback" ? 0 : 1, accounts: outcome === "rollback" ? 0 : 1,
      sessions: outcome === "rollback" ? 0 : 1,
      verification: outcome === "rollback" && !reuse ? [] : [{value: reuse ? "123456:0" : "654321:0", originalExpiry: reuse && outcome === "rollback"}]});
  });
}
afterAll(async () => { if (process.env.BACKGROUND_OTP_RESULTS) await Bun.write(`${process.env.BACKGROUND_OTP_RESULTS}/override-results.json`, JSON.stringify(traces, null, 2)); });
