import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { control, error, post, send, signup } from "../email-otp/helpers";

compatScenario("email OTP overrides default verification delivery", async (ctx) => {
  const email = ctx.uniqueEmail("otp-override");
  await signup(ctx, email);
  const sent = await post(ctx, "/send-verification-email", { email });
  expect(sent.status).toBe(200);
  const messages = await control(ctx, { email });
  expect(messages).toHaveLength(1);
  expect(messages[0]).toMatchObject({ email, type: "email-verification" });
  expect(await ctx.readVerificationEmail({ email })).toBeNull();
  const verified = await post(ctx, "/email-otp/verify-email", { email, otp: messages[0].otp });
  expect(verified.status).toBe(200);
  expect((verified.body as any).user.emailVerified).toBe(true);
  return { sent, verified };
});

compatScenario("encrypted email OTP reuse preserves the code and attempt budget", async (ctx) => {
  const email = ctx.uniqueEmail("otp-reuse");
  await signup(ctx, email);
  const otp = await send(ctx, email, "email-verification");
  const invalid = await post(ctx, "/email-otp/check-verification-otp", { email, type: "email-verification", otp: "incorrect" });
  error(invalid, 400, "INVALID_OTP");
  expect(await send(ctx, email, "email-verification")).toBe(otp);
  const remaining = [];
  for (let i = 0; i < 2; i++) {
    const response = await post(ctx, "/email-otp/check-verification-otp", { email, type: "email-verification", otp: "incorrect" });
    error(response, 400, "INVALID_OTP"); remaining.push(response);
  }
  const exhausted = await post(ctx, "/email-otp/verify-email", { email, otp });
  error(exhausted, 403, "TOO_MANY_ATTEMPTS");
  return { invalid, remaining, exhausted };
});

compatScenario("email OTP and email signup share phone plugin fields and reject unproven verification flags", async (ctx) => {
  const email = ctx.uniqueEmail("otp-phone");
  const otp = await send(ctx, email, "sign-in");
  const created = await post(ctx, "/sign-in/email-otp", { email, otp, phoneNumber: "+15550000011", phoneNumberVerified: false });
  expect(created.status).toBe(200);
  expect((created.body as any).user).toMatchObject({ phoneNumber: "+15550000011", phoneNumberVerified: null });
  const signup = await post(ctx, "/sign-up/email", { email: ctx.uniqueEmail("signup-phone"), name: "Phone Owner", password: "Password123!", phoneNumber: "+15550000012" });
  expect(signup.status).toBe(200);
  expect((signup.body as any).user).toMatchObject({ phoneNumber: "+15550000012", phoneNumberVerified: null });
  const protectedEmail = ctx.uniqueEmail("otp-phone-protected");
  const protectedOtp = await send(ctx, protectedEmail, "sign-in");
  const denied = await post(ctx, "/sign-in/email-otp", { email: protectedEmail, otp: protectedOtp, phoneNumber: "+15550000013", phoneNumberVerified: true });
  expect(denied.status).toBe(400);
  expect(denied.body).toEqual({ code: "FIELD_NOT_ALLOWED", message: "phoneNumberVerified is not allowed to be set" });
  return { created, signup, denied };
});
