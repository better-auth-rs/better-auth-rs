import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

const custom = process.env.COMPAT_PROFILE?.endsWith("custom");
const phone = "+15551230000";
const body = { phoneNumber: phone, code: "123456", unknown: "raw" };
async function call(ctx: any, input: any) {
  const response = await fetch(`${ctx.baseURL}/__test/phone-native`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ phone, ...input }) });
  expect(response.status).toBe(200);
  const value = await response.json();
  expect(value.fixtureError).toBeUndefined();
  return value;
}
const seed = (ctx: any, input: any = {}) => call(ctx, { action: "seed", ...input });

compatScenario("native phone consumption preserves raw hooks and projected verifier input without creating a user", async ctx => {
  await seed(ctx);
  const value = await call(ctx, { body, request: true, headers: { "X-Literal": "present" } });
  expect(value.result).toEqual({ status: true });
  expect(value.stored).toBeNull(); expect(value.users).toBe(0);
  expect(value.events[0]).toMatchObject({ phase: "before", path: "/", ambient: { $undefined: true }, body, request: "/original", header: "present" });
  expect(value.events.at(-1)).toMatchObject({ phase: "after", body });
  expect(value.events.some((event: any) => ["validator", "verified"].includes(event.phase))).toBe(false);
  if (custom) expect(value.events[1]).toMatchObject({ phase: "verify", path: "virtual:", ambient: "virtual:", body: { phoneNumber: phone, code: "123456" } });
  else {
    const replay = await call(ctx, { body });
    expect(replay.error).toEqual({ status: 400, body: { code: "OTP_NOT_FOUND", message: "OTP not found" } });
  }
  for (const path of ["consumePhoneNumberOTP", "phone-number/consume-otp"]) {
    const response = await fetch(`${ctx.baseURL}/api/auth/${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    expect(response.status).toBe(404);
  }
  return value;
});

compatScenario("native phone schema errors precede storage and still reach after hooks", async ctx => {
  await seed(ctx);
  const values = [];
  for (const input of [{}, { body: null }, { body: [] }, { body: {} }, { body: { phoneNumber: 7, code: false } }]) {
    const value = await call(ctx, input);
    expect(value.error.status).toBe(400); expect(value.error.body.code).toBe("VALIDATION_ERROR");
    expect(value.stored).toBe("123456:0");
    expect(value.events.map((event: any) => event.phase)).toEqual(["before", "after"]);
    values.push(value);
  }
  return values;
});

compatScenario("native phone before patches and response replacements preserve consumption timing", async ctx => {
  const values = [];
  for (const mode of ["patch", "stop", "replace", "after-error"]) {
    await seed(ctx);
    const value = await call(ctx, { mode, body: { ...body, code: mode === "patch" ? "wrong" : "123456" } });
    if (mode === "stop") { expect(value.result.status).toBe(false); expect(value.stored).toBe("123456:0"); expect(value.events.length).toBe(1); }
    else {
      expect(value.stored).toBeNull();
      if (mode === "after-error") expect(value.error).toEqual({ status: 400, body: { code: "AFTER_ERROR", message: "after rejected" } });
      else expect(value.result.status).toBe(mode === "patch");
    }
    if (mode === "patch") expect(value.events.at(-1).body).toEqual({ ...body, patched: true });
    values.push(value);
  }
  return values;
});

compatScenario("native phone consumption remains inside a borrowed transaction", async ctx => {
  const values = [];
  for (const rollback of [true, false]) {
    const identifier = `${phone}${rollback ? "1" : "2"}`;
    const value = await call(ctx, { action: "transaction", phone: identifier, body: { phoneNumber: identifier, code: "123456" }, rollback });
    expect(value.events.at(-1)).toEqual({ phase: "transaction", remains: false });
    expect(value.stored).toBeNull(); expect(value.users).toBe(0);
    if (rollback) expect(value.error).toEqual({ ordinary: true, message: "rollback requested" });
    else expect(value.result).toEqual({ status: true });
    values.push(value);
  }
  return values;
});

compatScenario("native phone verification failures preserve their attempt and deletion boundary", async ctx => {
  const values = [];
  if (custom) {
    for (const mode of ["custom-false", "custom-api", "custom-error"]) {
      await seed(ctx);
      const value = await call(ctx, { body, mode });
      expect(value.stored).toBe("123456:0");
      if (mode === "custom-error") { expect(value.error).toEqual({ ordinary: true, message: "verifier failed" }); expect(value.events.at(-1).phase).toBe("verify"); }
      else { expect(value.error.status).toBe(mode === "custom-api" ? 403 : 400); expect(value.events.at(-1).phase).toBe("after"); }
      values.push(value);
    }
  } else {
    for (const setup of [{ expired: true }, { value: "123456:2" }, {}]) {
      await seed(ctx, setup);
      const value = await call(ctx, { body: { ...body, code: "wrong" } });
      expect(value.error.body.code).toBe(setup.expired ? "OTP_EXPIRED" : setup.value ? "TOO_MANY_ATTEMPTS" : "INVALID_OTP");
      expect(value.stored).toBe(setup.expired || setup.value ? null : "123456:1");
      expect(value.events.at(-1).phase).toBe("after"); values.push(value);
    }
  }
  return values;
});
