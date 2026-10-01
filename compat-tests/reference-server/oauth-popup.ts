import { bearer, oauthPopup } from "better-auth/plugins";
import { createAuthEndpoint } from "better-auth/api";

export function createOAuthPopupFixture(profile: string, baseURL: string) {
  const enabled = profile.startsWith("oauth-popup-");
  let stateFailure = false;
  const events: unknown[] = [];
  return {
    options: enabled ? { trustedOrigins: [baseURL, "https://embed.example"], account: { storeStateStrategy: profile === "oauth-popup-cookie" ? "cookie" : "database" } } : {},
    providers: enabled ? ["popup", "popup-broken"].map(providerId => ({ providerId, clientId: "popup-client", clientSecret: "popup-secret", authorizationUrl: providerId === "popup" ? `${baseURL}/__test/oauth-popup/authorize` : "not a url", tokenUrl: `${baseURL}/__test/oauth-popup/token`, userInfoUrl: `${baseURL}/__test/oauth-popup/userinfo`, scopes: ["email"], pkce: true })) : [],
    plugins: enabled ? [{ id: "popup-probe", endpoints: { popupProbe: createAuthEndpoint("/oauth2/callback/probe", { method: "GET" }, async (ctx: any) => {
      if (ctx.query.mode === "plain") return ctx.json({ ordinary: true });
      if (ctx.query.mode === "token") ctx.setHeader("set-cookie", "better-auth.session_token=raw%2Btoken.signature%3D; Path=/; HttpOnly");
      if (ctx.query.mode === "combined") ctx.setHeader("set-cookie", "other=value; Expires=Wed, 21 Oct 2030 07:28:00 GMT, better-auth.session_token=first%2Btoken; Path=/");
      throw ctx.redirect(ctx.query.target ?? "/done");
    }) } }, bearer(), oauthPopup()] : [],
    hooks: enabled ? { verification: { create: { before() { if (stateFailure) throw new Error("Popup state unavailable"); } } } } : undefined,
    reset() { stateFailure = false; events.length = 0; },
    async route(request: Request, auth: any): Promise<Response | null> {
      const path = new URL(request.url).pathname;
      if (path === "/__test/oauth-popup/token") {
        const input = new URLSearchParams(await request.text());
        events.push({ event: "token", code: input.get("code"), verifierLength: input.get("code_verifier")?.length });
        return Response.json({ access_token: "popup-access", token_type: "Bearer", expires_in: 3600 });
      }
      if (path === "/__test/oauth-popup/userinfo") {
        events.push({ event: "userinfo", authorization: request.headers.get("authorization") });
        return Response.json({ id: "popup-user", email: "popup@example.com", emailVerified: true, name: "Popup User", image: null });
      }
      if (path !== "/__test/oauth-popup" || request.method !== "POST") return null;
      const body = await request.json();
      if (typeof body.stateFailure === "boolean") stateFailure = body.stateFailure;
      if (body.clear) events.length = 0;
      const context = await auth.$context;
      const state = body.state ? await context.internalAdapter.findVerificationValue(body.state) : null;
      return Response.json({ events, value: state?.value ?? null });
    },
  };
}
