import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

export async function loadUpstream(modules: string) {
  const { betterAuth } = await import(`${modules}/better-auth/dist/auth/minimal.mjs`);
  const plugins = await import(`${modules}/better-auth/dist/plugins/index.mjs`);
  const { apiKey } = await import(`${modules}/@better-auth/api-key/dist/index.mjs`);
  const { passkey } = await import(`${modules}/@better-auth/passkey/dist/index.mjs`);
  const { getEndpoints } = await import(`${modules}/better-auth/dist/api/index.mjs`);
  const { generator } = await import(`${modules}/better-auth/dist/plugins/open-api/generator.mjs`);
  const { createAccessControl } = await import(`${modules}/better-auth/dist/plugins/access/index.mjs`);
  const { defaultStatements } = await import(`${modules}/better-auth/dist/plugins/organization/access/index.mjs`);

  const versions = Object.fromEntries(await Promise.all([
    "better-auth", "@better-auth/core", "@better-auth/api-key", "@better-auth/passkey", "zod",
  ].map(async name => [name, JSON.parse(await readFile(`${modules}/${name}/package.json`, "utf8")).version])));
  for (const name of ["better-auth", "@better-auth/core", "@better-auth/api-key", "@better-auth/passkey"]) {
    assert.equal(versions[name], "1.7.6", `Review the descriptors before changing ${name}`);
  }

  let policyCalls = 0;
  function forbiddenPolicy() {
    policyCalls++;
    throw new Error("Documentation generation must not execute application policies");
  }
  function organization(teams: boolean, roles: boolean, schema = {}) {
    return plugins.organization({
      teams: { enabled: teams }, dynamicAccessControl: { enabled: roles },
      ac: createAccessControl(defaultStatements), schema,
    });
  }
  const factories: [string, () => any | null][] = [
    ["core", () => null],
    ["organization", () => organization(true, true)],
    ["api-key", () => apiKey()],
    ["passkey", () => passkey()],
    ["admin", () => plugins.admin()],
    ["anonymous", () => plugins.anonymous()],
    ["bearer", () => plugins.bearer()],
    ["device-authorization", () => plugins.deviceAuthorization()],
    ["custom-session", () => plugins.customSession(forbiddenPolicy)],
    ["generic-oauth", () => plugins.genericOAuth({ config: [{
      providerId: "descriptor-provider", clientId: "descriptor-client", clientSecret: "descriptor-secret",
      authorizationUrl: "https://provider.example/authorize", tokenUrl: "https://provider.example/token",
      userInfoUrl: "https://provider.example/userinfo", scopes: ["email"],
    }] })],
    ["have-i-been-pwned", () => plugins.haveIBeenPwned()],
    ["email-otp", () => plugins.emailOTP({ sendVerificationOTP: forbiddenPolicy })],
    ["jwt", () => plugins.jwt()],
    ["magic-link", () => plugins.magicLink({ sendMagicLink: forbiddenPolicy })],
    ["multi-session", () => plugins.multiSession()],
    ["oauth-proxy", () => plugins.oAuthProxy()],
    ["oauth-popup", () => plugins.oauthPopup()],
    ["one-tap", () => plugins.oneTap({ clientId: "descriptor-client" })],
    ["one-time-token", () => plugins.oneTimeToken()],
    ["phone-number", () => plugins.phoneNumber()],
    ["siwe", () => plugins.siwe({ domain: "localhost", getNonce: forbiddenPolicy, verifyMessage: forbiddenPolicy })],
    ["two-factor", () => plugins.twoFactor()],
    ["username", () => plugins.username()],
    ["captcha", () => plugins.captcha({ provider: "cloudflare-turnstile", secretKey: "descriptor-secret" })],
    ["last-login-method", () => plugins.lastLoginMethod()],
    ["open-api", () => plugins.openAPI()],
  ];
  async function context(plugin: any | null, overrides: any = {}) {
    return await betterAuth({
      baseURL: "https://descriptor.example.test", secret: "endpoint-descriptor-secret-at-least-thirty-two-characters",
      logger: { disabled: true }, emailAndPassword: { enabled: true }, ...overrides, plugins: plugin ? [plugin] : [],
    }).$context;
  }
  const { getAuthTables } = await import(`${modules}/@better-auth/core/dist/db/get-tables.mjs`);
  return { versions, factories, context, organization, generator, getEndpoints, getAuthTables,
    plugins, apiKey, forbiddenPolicy, policyCalls: () => policyCalls };
}
