import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { genericOAuth, gumroad, hubspot, patreon, slack, yandex } from "better-auth/plugins/generic-oauth";

const helpers = { gumroad, hubspot, patreon, slack, yandex };
const credentials = { clientId: "preset-client", clientSecret: "preset-secret" };
const tokens = { accessToken: "ordinary-profile-token" };
const authorization = {
  state: "preset-state",
  codeVerifier: "ordinary-preset-verifier",
  redirectURI: "https://app.example.test/api/auth/oauth2/callback/preset",
  scopes: ["request-scope"],
  loginHint: "reader@example.test",
  additionalParams: { display: "popup" },
};

const configurations = [
  { name: "default", options: {} },
  { name: "empty-scopes", options: { scopes: [] } },
  {
    name: "configured",
    options: {
      scopes: ["custom-scope", "custom-scope"],
      tokenEndpointAuth: { method: "client_secret_basic" },
      redirectURI: "https://app.example.test/configured-callback",
      endSessionEndpoint: "https://identity.example.test/logout",
      postLogoutRedirectURI: "https://app.example.test/signed-out",
      disableProviderLogout: true,
      pkce: false,
      disableImplicitSignUp: true,
      disableSignUp: true,
      overrideUserInfo: true,
    },
  },
];

const inputs = [
  { provider: "gumroad", name: "user", response: { success: true, user: { user_id: "gumroad-reader", name: "Gumroad Reader", email: "gumroad@example.test", profile_url: "https://images.example.test/gumroad.png" } } },
  { provider: "gumroad", name: "no-user", response: { success: true } },
  { provider: "gumroad", name: "unsuccessful", response: { success: false, user: { user_id: "unused" } } },
  { provider: "hubspot", name: "numeric-id", response: { user_id: 1729, user: "hubspot@example.test" } },
  { provider: "hubspot", name: "signed-id", response: { user_id: null, signed_access_token: { userId: 2048 }, user: "signed@example.test" } },
  { provider: "hubspot", name: "zero-id", response: { user_id: 0, signed_access_token: { userId: 2048 }, user: "unused@example.test" } },
  { provider: "patreon", name: "attributes", response: { data: { id: "patreon-reader", attributes: { full_name: "Patreon Reader", email: "patreon@example.test", image_url: "https://images.example.test/patreon.png", is_email_verified: true } } } },
  { provider: "patreon", name: "null-image", response: { data: { id: "patreon-second", attributes: { full_name: "Second Reader", email: "second@example.test", image_url: null, is_email_verified: false } } } },
  { provider: "slack", name: "picture", response: { sub: "slack-reader", name: "Slack Reader", email: "slack@example.test", picture: "https://images.example.test/slack.png", email_verified: true } },
  { provider: "slack", name: "fallback-picture", response: { sub: "slack-second", name: "Second Reader", email: "second@example.test", picture: null, "https://slack.com/user_image_512": "https://images.example.test/slack-fallback.png", email_verified: null } },
  { provider: "slack", name: "empty-picture", response: { sub: "slack-third", name: "Third Reader", email: "third@example.test", picture: "", "https://slack.com/user_image_512": "https://images.example.test/unused.png" } },
  { provider: "yandex", name: "avatar", response: { id: "yandex-reader", default_email: "yandex@example.test", display_name: "Yandex Reader", is_avatar_empty: false, default_avatar_id: "avatar-123" } },
  { provider: "yandex", name: "email-and-name-fallback", response: { id: "yandex-second", default_email: null, emails: ["second@example.test"], display_name: null, real_name: "Second Reader", is_avatar_empty: true, default_avatar_id: "unused" } },
  { provider: "yandex", name: "login-name", response: { id: "yandex-third", emails: ["third@example.test"], display_name: null, real_name: null, first_name: null, login: "reader-login" } },
  { provider: "yandex", name: "empty-email", response: { id: "unused", default_email: "", emails: ["unused@example.test"] } },
  ...Object.keys(helpers).map(provider => ({ provider, name: "http-error", status: 503, response: { message: "Profile service unavailable" } })),
];

function json(value) {
  return JSON.parse(JSON.stringify(value));
}

async function resolved(config) {
  const auth = betterAuth({
    secret: "generic-presets-contract-secret-at-least-32-characters",
    baseURL: "https://app.example.test",
    logger: { disabled: true },
    telemetry: { enabled: false },
    plugins: [genericOAuth({ config: [config] })],
  });
  const context = await auth.$context;
  const provider = context.socialProviders.find(value => value.id === config.providerId);
  assert.ok(provider, `Missing ${config.providerId} provider`);
  return provider;
}

export async function captureGenericProfilePresets() {
  const packageJson = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8"));
  assert.equal(packageJson.version, "1.7.6");
  const configs = [];
  for (const [id, helper] of Object.entries(helpers)) {
    for (const input of configurations) {
      const config = helper({ ...credentials, ...input.options });
      const provider = await resolved(config);
      const url = await provider.createAuthorizationURL(authorization);
      configs.push({ provider: id, ...input, expected: { config: json(config), authorizationURL: url.href } });
    }
  }
  const cases = [];
  for (const input of inputs) {
    const events = [];
    const requests = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = Object.assign(async (resource, init) => {
      const request = new Request(resource, init);
      requests.push({ url: request.url, method: request.method, headers: Object.fromEntries(request.headers), body: await request.text() });
      events.push("http");
      return Response.json(input.response, { status: input.status ?? 200 });
    }, originalFetch);
    try {
      const config = helpers[input.provider](credentials);
      const profile = await config.getUserInfo(tokens);
      const expected = { profile: json(profile), requests };
      if (profile !== null) {
        expected.rawSubject = await config.accountSubject({ profile, tokens });
        expected.accountId = String(expected.rawSubject);
        const mapperInputs = [];
        config.mapProfileToUser = async profile => {
          events.push("map");
          mapperInputs.push(json(profile));
          return { name: "Mapped Reader", email: "mapped@example.test", emailVerified: true, favoriteColor: "blue" };
        };
        const provider = await resolved(config);
        expected.mapped = json(await provider.getUserInfo(tokens));
        expected.mapperInputs = mapperInputs;
      }
      expected.events = events;
      cases.push({ ...input, expected });
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
  return { version: packageJson.version, credentials, tokens, authorization, configs, cases };
}

if (import.meta.main) {
  const output = JSON.stringify(await captureGenericProfilePresets(), null, 2) + "\n";
  if (process.env.GENERIC_PROFILE_PRESETS_OUTPUT) writeFileSync(process.env.GENERIC_PROFILE_PRESETS_OUTPUT, output);
  else process.stdout.write(output);
}
