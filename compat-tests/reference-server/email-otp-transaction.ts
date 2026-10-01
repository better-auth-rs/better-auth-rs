import { emailOTP } from "better-auth/plugins";

export function createEmailOtpTransactionFixture(profile: string) {
  const enabled = profile === "email-otp-transaction";
  let deny = false;
  let auth: any;
  const events: any[] = [];
  return {
    enabled,
    verification: enabled ? { storeIdentifier: "hashed" as const } : {},
    emailAndPassword: enabled ? {
      password: {
        hash: async (password: string) => `fixture:${password}`,
        verify: async ({ hash, password }: any) => hash === `fixture:${password}`,
      },
    } : {},
    plugins: enabled ? [emailOTP({ generateOTP: () => "123456", sendVerificationOTP: async () => {} })] : [],
    user: enabled ? {
      async validateUserInfo(data: any) {
        const email = data.user.email;
        const before = await auth.api.getVerificationOTP({ query: { email, type: "sign-in" } });
        const created = await auth.api.createVerificationOTP({ body: { email, type: "sign-in" } });
        const readBack = await auth.api.getVerificationOTP({ query: { email, type: "sign-in" } });
        events.push({ before: before.otp, created, readBack: readBack.otp });
        if (deny) return { error: "otp_admission_denied" };
      },
    } : {},
    reset() { deny = false; events.length = 0; },
    async route(request: Request, instance: any): Promise<Response | null> {
      if (!enabled || new URL(request.url).pathname !== "/__test/email-otp-transaction" || request.method !== "POST") return null;
      auth = instance;
      const body = await request.json();
      if (typeof body.deny === "boolean") deny = body.deny;
      const email = body.email ?? "missing@example.com";
      const identifier = `sign-in-otp-${email.toLowerCase()}`;
      const context = await auth.$context;
      const record = await context.internalAdapter.findVerificationValue(identifier);
      const { otp } = await auth.api.getVerificationOTP({ query: { email, type: "sign-in" } });
      const user = await context.internalAdapter.findUserByEmail(email);
      return Response.json({ events, otp, userExists: !!user, identifierHashed: record ? record.identifier !== identifier : null });
    },
  };
}
