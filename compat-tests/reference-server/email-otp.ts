import { Database } from "bun:sqlite";
import { emailOTP } from "better-auth/plugins";

export function createEmailOtpFixture(database: Database, profile: string) {
  const outbox = new Map<string, { email: string; otp: string; type: string }[]>();
  let fails = false;
  const plugin = emailOTP({
    changeEmail: { enabled: true, verifyCurrentEmail: true },
    disableSignUp: profile === "email-otp-options",
    storeOTP: profile === "email-otp-options" ? "hashed" : profile === "email-otp-reuse" ? "encrypted" : "plain",
    resendStrategy: profile === "email-otp-options" || profile === "email-otp-reuse" ? "reuse" : "rotate",
    sendVerificationOnSignUp: profile === "email-otp-options",
    overrideDefaultEmailVerification: profile === "email-otp" || profile === "email-otp-reuse",
    async sendVerificationOTP(message) {
      if (fails) throw new Error("compat OTP sender failure");
      outbox.set(message.email, [...(outbox.get(message.email) ?? []), message]);
    },
  });
  return {
    plugin,
    reset() { outbox.clear(); fails = false; },
    async handle(request: Request): Promise<Response | null> {
      if (new URL(request.url).pathname !== "/__test/email-otp" || request.method !== "POST") return null;
      const body = await request.json();
      if (body.action === "expire") {
        database.query('UPDATE "verification" SET "expiresAt" = ? WHERE "identifier" = ?').run(Date.now() - 1000, `${body.type}-otp-${body.email}`);
        return Response.json({ success: true });
      }
      if (body.action === "fail") { fails = body.fail; return Response.json({ success: true }); }
      return Response.json(outbox.get(body.email) ?? []);
    },
  };
}
