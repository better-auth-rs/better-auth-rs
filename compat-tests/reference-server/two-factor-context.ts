import { APIError } from "better-auth/api";
import type { twoFactor } from "better-auth/plugins";

type Send = NonNullable<NonNullable<NonNullable<Parameters<typeof twoFactor>[0]>["otpOptions"]>["sendOTP"]>;

export function createTwoFactorContextFixture(outbox: Map<string, { otp: string }>) {
  const events: unknown[] = [];
  const sendOTP: Send = async ({ user, otp }, ctx) => {
    const stored = await ctx!.context.internalAdapter.findUserById(user.id);
    events.push({
      user: { id: user.id, email: user.email, secretNote: user.secretNote ?? null },
      databaseUser: { id: stored!.id, email: stored!.email },
      path: ctx!.path ?? null,
      requestPath: ctx!.request ? new URL(ctx!.request.url).pathname.replace(/^\/api\/auth/, "") : null,
      body: ctx!.body,
      header: ctx!.request?.headers.get("x-callback-tag") ?? null,
      sessionEmail: ctx!.context.session?.user.email ?? null,
      hasResponse: ctx!.context.returned !== undefined,
      otpLength: otp.length,
    });
    outbox.set(user.email, { otp });
    if (ctx!.request?.headers.get("x-callback-fail") === "send") {
      throw new APIError("SERVICE_UNAVAILABLE", { code: "DELIVERY_UNAVAILABLE", message: "Fixture delivery unavailable" });
    }
  };
  return {
    sendOTP,
    reset() { events.length = 0; },
    async handle(request: Request): Promise<Response | null> {
      if (new URL(request.url).pathname !== "/__test/two-factor-context" || request.method !== "POST") return null;
      const body = await request.json();
      if (body.action === "clear") events.length = 0;
      return Response.json(events);
    },
  };
}
