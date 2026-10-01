import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { genericOAuth } from "better-auth/plugins";

for (const sqlite of [false, true]) {
  test(`${sqlite ? "SQLite" : "Memory"} preserves scopes on sign-in and merges scopes on explicit linking`, async () => {
    for (const updateAccountOnSignIn of [false, true]) {
      let scopes = [" stored ", "common", "", "dup", "common"];
      let accessToken = "first-token";
      const database = sqlite ? new Database(":memory:") : undefined;
      const auth = betterAuth({
        database,
        secret: "oauth-scope-contract-secret-at-least-32-characters",
        baseURL: "http://scopes.test",
        logger: { disabled: true },
        account: { skipStateCookieCheck: true, storeAccountCookie: true, updateAccountOnSignIn },
        plugins: [genericOAuth({ config: [{
          providerId: "generic", clientId: "fixture-client",
          authorizationUrl: "https://provider.example/authorize",
          getToken: async () => ({ accessToken, scopes }),
          getUserInfo: async () => ({ id: "subject", name: "Owner", email: "owner@scopes.test", emailVerified: true }),
        }] })],
      });
      if (database) await (await getMigrations(auth.options)).runMigrations();
      const finish = async (start: { response: { url?: string }, headers: Headers }) => {
        const state = new URL(start.response.url!).searchParams.get("state");
        const headers = new Headers({cookie: start.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ")});
        const response = await auth.handler(new Request(`http://scopes.test/api/auth/callback/generic?code=code&state=${encodeURIComponent(state!)}`, {headers}));
        expect(response.status).toBe(302);
        expect(response.headers.get("location")).toBe("http://scopes.test/done");
        return response;
      };
      const signin = () => auth.api.signInSocial({ body: { provider: "generic", callbackURL: "http://scopes.test/done", disableRedirect: true }, returnHeaders: true });
      const first = await finish(await signin());
      const headers = new Headers({ cookie: first.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ") });
      const ctx = await auth.$context;
      const key = { providerId: "generic", accountId: "subject" };
      expect((await ctx.internalAdapter.findAccountByKey(key))?.scope).toBe(" stored ,common,,dup,common");
      scopes = [" new ", "common", "", "new"];
      accessToken = "second-token";
      const signedIn = await finish(await signin());
      const afterSignin = await ctx.internalAdapter.findAccountByKey(key);
      expect(afterSignin?.scope).toBe(" stored ,common,,dup,common");
      expect(afterSignin?.accessToken).toBe(updateAccountOnSignIn ? "second-token" : "first-token");
      const cookieHeaders = new Headers({cookie: signedIn.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ")});
      const token = await auth.api.getAccessToken({headers: cookieHeaders, body: {useAccountCookie: true}});
      expect(token.scopes).toEqual(["stored", "common", "dup", "common"]);
      expect(token.accessToken).toBe(updateAccountOnSignIn ? "second-token" : "first-token");
      const link = await auth.api.linkSocialAccount({ headers, body: { provider: "generic", callbackURL: "http://scopes.test/done", disableRedirect: true }, returnHeaders: true });
      await finish(link);
      const linked = await ctx.internalAdapter.findAccountByKey(key);
      expect(linked?.scope).toBe("stored,common,dup,new");
      expect(linked?.accessToken).toBe("second-token");
      database?.close();
    }
  });
}
