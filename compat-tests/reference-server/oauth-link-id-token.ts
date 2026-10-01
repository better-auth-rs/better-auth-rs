import { decryptOAuthToken, setTokenUtil } from "better-auth/oauth2";

export function createOAuthLinkIdTokenFixture(profile: string) {
  const enabled = profile.startsWith("oauth-link-id-token");
  let provider: any = {};
  let failure = "";
  let admissions = 0;
  const events: string[] = [];
  const imageUpdates: Array<{ image?: string | null }> = [];
  function hook(name: string, ctx: any) {
    if (ctx?.path !== "/link-social") return;
    events.push(name);
    if (failure === name) throw new Error(`fixture ${name}`);
    if (failure === `${name}.cancel`) return false;
  }
  return {
    enabled,
    account: {
      encryptOAuthTokens: true,
      accountLinking: { enabled: profile !== "oauth-link-id-token-disabled", updateUserInfoOnLink: true, trustedProviders: [], allowDifferentEmails: false },
    },
    user: {
      additionalFields: {
        department: { type: "string" as const, required: false },
        internalCode: { type: "string" as const, required: false, input: false, defaultValue: "protected" },
      },
      async validateUserInfo() { admissions++; },
    },
    google: {
      clientId: "fixture-google", clientSecret: "fixture-secret",
      verifyIdToken: async () => true,
      getUserInfo: async () => ({ user: provider, data: { ...provider, sub: provider.id } }),
    },
    databaseHooks: {
      account: {
        create: { before: async (account: any, ctx: any) => {
          if (account.providerId === "nested-cancel") { events.push("account.create.nested"); return false; }
          const result = hook("account.create.before", ctx);
          if (ctx?.path === "/link-social" && failure === "account.create.nested") {
            const nested = await ctx.context.internalAdapter.createAccount({ ...account, providerId: "nested-cancel", accountId: `${account.accountId}.nested` });
            if (!nested) throw new Error("Nested account creation cancelled");
          }
          return result;
        }, after: async (_: any, ctx: any) => { hook("account.create.after", ctx); } },
        update: { before: async (_: any, ctx: any) => hook("account.update.before", ctx), after: async (_: any, ctx: any) => { hook("account.update.after", ctx); } },
      },
      user: { update: { before: async (row: any, ctx: any) => {
        if (ctx?.path === "/link-social") imageUpdates.push(row.image === undefined ? {} : { image: row.image });
        hook("user.update.before", ctx);
      }, after: async (_: any, ctx: any) => { hook("user.update.after", ctx); } } },
    },
    reset() { provider = {}; failure = ""; admissions = 0; events.length = 0; imageUpdates.length = 0; },
    async route(request: Request, auth: any): Promise<Response | null> {
      if (!enabled || new URL(request.url).pathname !== "/__test/oauth-link-id-token" || request.method !== "POST") return null;
      const body = await request.json();
      if (body.provider) provider = body.provider;
      if (typeof body.failure === "string") failure = body.failure;
      if (body.clear) { events.length = 0; imageUpdates.length = 0; admissions = 0; }
      const context = await auth.$context;
      const user = body.email ? (await context.internalAdapter.findUserByEmail(body.email))?.user : null;
      if (body.seed && user) {
        await context.internalAdapter.createAccount({ userId: user.id, providerId: "google", accountId: provider.id, accessToken: await setTokenUtil("seed-access", context), refreshToken: await setTokenUtil("seed-refresh", context), idToken: "seed-id", scope: "seed-scope" });
      }
      const accounts = user ? await context.internalAdapter.findAccounts(user.id) : [];
      const account = accounts.find((row: any) => row.providerId === "google");
      const access = account ? await decryptOAuthToken(account.accessToken, context) : null;
      const refresh = account ? await decryptOAuthToken(account.refreshToken, context) : null;
      return Response.json({
        events, imageUpdates, admissions, nestedAccounts: accounts.filter((row: any) => row.providerId === "nested-cancel").length,
        user: user ? { name: user.name, email: user.email, emailVerified: user.emailVerified, image: user.image ?? null, department: user.department ?? null, internalCode: user.internalCode ?? null } : null,
        account: account ? { accessToken: access ?? null, refreshToken: refresh ?? null, idToken: account.idToken ?? null, scope: account.scope ?? null, accessTokenExpiresAt: account.accessTokenExpiresAt ?? null, encrypted: !!access && account.accessToken !== access } : null,
      });
    },
  };
}
