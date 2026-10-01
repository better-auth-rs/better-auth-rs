import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

export async function runDynamicOAuth() {
  const database = new Database(":memory:");
  const options: any = {
    database, secret: "dynamic-oauth-fixture-secret-at-least-thirty-two-characters",
    baseURL: { allowedHosts: ["*.tenant.test"] },
    logger: { disabled: true }, rateLimit: { enabled: false },
    account: { accountLinking: { enabled: true, trustedProviders: async (request?: Request) => request?.headers.get("host") === "a.tenant.test" ? ["google"] : [] } },
    socialProviders: { google: { clientId: "fixture-google", clientSecret: "fixture-secret", verifyIdToken: async () => true, getUserInfo: async (token: any) => {
      const user = JSON.parse(token.idToken);
      return { user, data: { ...user, sub: user.id } };
    } } },
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  const context = await auth.$context;
  const results = [];
  for (const tenant of ["b", "a"]) {
    const email = `${tenant}@tenant.test`;
    const user = await context.adapter.create({ model: "user", data: { email, name: tenant, emailVerified: true, createdAt: new Date(), updatedAt: new Date() } });
    const request = (body: any) => new Request(`https://${tenant}.tenant.test/api/auth/sign-in/social`, { method: "POST", headers: { host: `${tenant}.tenant.test`, "content-type": "application/json" }, body: JSON.stringify(body) });
    const response = await auth.handler(request({ provider: "google", idToken: { token: JSON.stringify({ id: `provider-${tenant}`, email, name: tenant, emailVerified: false }) } }));
    const body = await response.json();
    const accounts = await context.internalAdapter.findAccounts(user.id);
    const authorization = await auth.handler(request({ provider: "google", callbackURL: `https://${tenant}.tenant.test/done`, disableRedirect: true }));
    const url = new URL((await authorization.json()).url);
    const state = url.searchParams.get("state")!;
    const stored = await context.internalAdapter.findVerificationValue(state);
    const payload = stored ? JSON.parse(stored.value) : null;
    results.push({ tenant, status: response.status, error: body.message ?? null, signedIn: !!body.token, accounts: accounts.map((row: any) => ({ providerId: row.providerId, accountId: row.accountId, sameUser: row.userId === user.id })), redirectURI: url.searchParams.get("redirect_uri"), statePersisted: !!stored, stateCallback: payload?.callbackURL, stateBound: payload?.oauthState === state });
  }
  database.close();
  return results;
}
