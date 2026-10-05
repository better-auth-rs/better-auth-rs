import { beforeAll, expect, test } from "bun:test";
import { discord, line, paypal, railway, reddit } from "@better-auth/core/social-providers";

beforeAll(async () => {
  const core = await Bun.file(new URL("../node_modules/@better-auth/core/package.json", import.meta.url)).json();
  expect(core.version).toBe("1.7.6");
});

const key = "ordinary-client-key";
const cases = [
  { name: "discord", constructor: discord, key, sentKey: key, basic: false, verifier: false, accept: "application/json", endpoint: "https://discord.com/api/oauth2/token" },
  { name: "railway", constructor: railway, key, sentKey: key, basic: true, verifier: true, accept: "application/json", endpoint: "https://backboard.railway.com/oauth/token" },
  { name: "line", constructor: line, key, sentKey: key, basic: false, verifier: true, accept: "application/json", endpoint: "https://api.line.me/oauth2/v2.1/token" },
  { name: "paypal", constructor: paypal, key, sentKey: undefined, basic: true, verifier: true, accept: "application/json", endpoint: "https://api-m.sandbox.paypal.com/v1/oauth2/token" },
  { name: "reddit", constructor: reddit, key, sentKey: undefined, basic: true, verifier: false, accept: "text/plain", endpoint: "https://www.reddit.com/api/v1/access_token" },
  { name: "discord omitted", constructor: discord, key: undefined, sentKey: undefined, basic: false, verifier: false, accept: "application/json", endpoint: "https://discord.com/api/oauth2/token" },
  { name: "discord empty", constructor: discord, key: "", sentKey: undefined, basic: false, verifier: false, accept: "application/json", endpoint: "https://discord.com/api/oauth2/token" },
];

for (const sample of cases) {
  test(`${sample.name} clientKey follows the pinned code and refresh option paths`, async () => {
    const provider = sample.constructor({
      clientId: "client",
      clientSecret: "secret",
      ...(sample.key === undefined ? {} : { clientKey: sample.key }),
    });
    const originalFetch = globalThis.fetch;
    const requests: unknown[] = [];
    const response = { access_token: "ordinary-access", refresh_token: "ordinary-refresh", token_type: "Bearer" };
    globalThis.fetch = Object.assign(async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const request = new Request(input, init);
      requests.push({
        url: request.url,
        method: request.method,
        contentType: request.headers.get("content-type"),
        accept: request.headers.get("accept"),
        authorization: request.headers.get("authorization"),
        body: Object.fromEntries(new URLSearchParams(await request.text())),
      });
      return Response.json(response);
    }, originalFetch);
    try {
      const code = await provider.validateAuthorizationCode({
        code: "ordinary-code",
        redirectURI: "https://app.example.test/callback/provider",
        codeVerifier: "ordinary-code-verifier",
        deviceId: "ordinary-device",
      });
      const refresh = await provider.refreshAccessToken("ordinary-refresh");
      const credentials = sample.basic ? {} : { client_id: "client", client_secret: "secret" };
      const common = {
        url: sample.endpoint,
        method: "POST",
        contentType: "application/x-www-form-urlencoded",
        authorization: sample.basic ? "Basic Y2xpZW50OnNlY3JldA==" : null,
      };
      expect(requests).toStrictEqual([
        {
          ...common,
          accept: sample.accept,
          body: {
            grant_type: "authorization_code",
            code: "ordinary-code",
            redirect_uri: "https://app.example.test/callback/provider",
            ...(sample.sentKey === undefined ? {} : { client_key: sample.sentKey }),
            ...(sample.verifier ? { code_verifier: "ordinary-code-verifier" } : {}),
            ...credentials,
          },
        },
        {
          ...common,
          accept: "application/json",
          body: { grant_type: "refresh_token", refresh_token: "ordinary-refresh", ...credentials },
        },
      ]);
      expect(JSON.parse(JSON.stringify([code, refresh]))).toStrictEqual([
        { accessToken: "ordinary-access", refreshToken: "ordinary-refresh", tokenType: "Bearer", scopes: [], raw: response },
        { accessToken: "ordinary-access", refreshToken: "ordinary-refresh", tokenType: "Bearer", scopes: [] },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
}
