import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("native OTP create and get share the admission transaction", async ctx => {
  const email = ctx.uniqueEmail("otp-transaction");
  const control = async (deny: boolean) => {
    const response = await fetch(`${ctx.baseURL}/__test/email-otp-transaction`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, deny }),
    });
    expect(response.status).toBe(200);
    return await response.json();
  };
  await control(true);
  const rejected = await ctx.actor().client.signUp.email({ email, name: "OTP Transaction", password: "Password123!" });
  expect(rejected.error).toMatchObject({ status: 403, code: "otp_admission_denied" });
  const rolledBack = await control(false);
  expect(rolledBack).toEqual({ events: [{ before: null, created: "123456", readBack: "123456" }], otp: null, userExists: false, identifierHashed: null });
  const accepted = await ctx.actor().client.signUp.email({ email, name: "OTP Transaction", password: "Password123!" });
  expect(accepted.error).toBeNull();
  const committed = await control(false);
  expect(committed).toEqual({
    events: [
      { before: null, created: "123456", readBack: "123456" },
      { before: null, created: "123456", readBack: "123456" },
    ],
    otp: "123456", userExists: true, identifierHashed: true,
  });
  return { rejected, rolledBack, accepted, committed };
}, 30_000);
