import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";
import { control, error, post, send, signup } from "../email-otp/helpers";

compatScenario("email OTP signup hook delivers verification and disabled signup does not issue unknown-user codes", async (ctx) => {
  const email = ctx.uniqueEmail("otp-hook");
  await signup(ctx, email);
  const messages = await control(ctx, { email });
  expect(messages).toHaveLength(1);
  expect(messages[0]).toMatchObject({ email, type: "email-verification" });
  const verified = await post(ctx, "/email-otp/verify-email", { email, otp: messages[0].otp });
  expect(verified.status).toBe(200);
  expect((verified.body as any).token).toBeString();
  const session = await ctx.actor().client.getSession();
  expect(session.data?.user.id).toBe((verified.body as any).user.id);
  const unknownEmail = ctx.uniqueEmail("otp-disabled");
  const unknown = await post(ctx, "/email-otp/send-verification-otp", { email: unknownEmail, type: "sign-in" });
  expect(unknown.status).toBe(200);
  expect(await control(ctx, { email: unknownEmail })).toEqual([]);
  const denied = await post(ctx, "/sign-in/email-otp", { email: unknownEmail, otp: "000000" });
  error(denied, 400, "INVALID_OTP");
  const otp = await send(ctx, email, "sign-in");
  const signedIn = await post(ctx, "/sign-in/email-otp", { email, otp });
  expect(signedIn.status).toBe(200);
  return { verified, session, unknown, denied, signedIn };
});
