#!/usr/bin/env bun
import {createTwoFactorAfterFixture} from "./two-factor-after";
import {createPhoneNativeFixture} from "./phone-native";
import {createNativeDispatchFixture} from "./native-dispatch";
import { routeAccountHttpOutput } from "./account-http-output";
import { routeAccountVerificationFields } from "./account-verification-fields";
import { routeVerificationDateOutput } from "./verification-date-output";
import { createDynamicContextFixture } from "./dynamic-context";
import { runOpenApi } from "./openapi";
import { createOAuthPopupFixture } from "./oauth-popup";
import { mappedPluginSchema, mappedPluginExtras } from "./plugin-schema";
import { createOrganizationCallbacks } from "./organization-callbacks";
import { organizationFieldOptions } from "./organization-fields";
import { organizationCoreFieldOptions } from "./organization-core-fields";
import { organizationMemberFieldOptions } from "./organization-member-fields";
import { organizationDynamicFieldOptions } from "./organization-dynamic-fields";
import { organizationNativeJsonOptions } from "./organization-native-json";

import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { apiKey } from "@better-auth/api-key";
import { createApiKeyCallbacks } from "./api-key-callbacks";
import { admin, bearer, deviceAuthorization, twoFactor, username } from "better-auth/plugins";
import { createAdminOptionsFixture } from "./admin-options";
import { createStatelessFixture } from "./stateless";
import { createLastLoginFixture } from "./last-login";
import { createUsernameFixture } from "./username-options";
import { createTrailingSlashesFixture } from "./trailing-slashes";
import { createApiErrorFixture } from "./api-error";
import { createRequestQueryFixture } from "./request-query";
import { createDispatchErrorsFixture } from "./dispatch-errors";
import { createIdentityContextFixture } from "./identity-context";
import { createRateLimitFixture } from "./rate-limit-options";
import { organization } from "better-auth/plugins/organization";
import { createAccessControl } from "better-auth/plugins/access";
import { defaultStatements } from "better-auth/plugins/organization/access";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { oAuthProxy } from "better-auth/plugins/oauth-proxy";
import { createEmailOtpFixture } from "./email-otp";
import { createEmailOtpNativeFixture } from "./email-otp-native";
import { createEmailOtpTransactionFixture } from "./email-otp-transaction";
import { httpBodyOptions } from "./http-body";
import { createOAuthLinkIdTokenFixture } from "./oauth-link-id-token";
import { createSecondaryStorageFixture } from "./secondary-storage";
import { sessionFieldOptions } from "./session-fields";
import { createCookieVersionFixture } from "./cookie-version";
import { passwordPolicyOptions } from "./password-policy";
import { createAuthLifecycleFixture } from "./auth-lifecycle";
import { createCaptchaFixture } from "./captcha";
import { createCryptoFixture } from "./crypto";
import { createUserAdmissionFixture } from "./user-admission";
import { createDeviceGenerators } from "./device-generators";
import { createPasswordSecurityFixture } from "./password-security";
import { signupEnumerationOptions } from "./signup-enumeration";
import { createPasskeyOptions } from "./passkey-options";
import { createCustomSessionFixture } from "./custom-session";
import { createOtpCallbacksFixture } from "./otp-callbacks";
import { createTwoFactorContextFixture } from "./two-factor-context";
import { twoFactorOptions, twoFactorOptionsState } from "./two-factor-options";
import { createApiKeyStorageFixture } from "./api-key-storage";
import { createOneTapFixture } from "./one-tap";
import { createIdentityFixture } from "./identity-routes";
import { userFields } from "./user-fields";
import { tokenRoutePlugins } from "./token-routes";
import { createJwtFixture } from "./jwt-fixture";
import { createJwtAdapterFixture } from "./jwt-adapter";
import { createStandaloneDatabaseLifecycleFixture } from "./database-lifecycle";

function getPort() {
  const idx = process.argv.indexOf("--port");
  if (idx !== -1 && process.argv[idx + 1]) {
    return Number(process.argv[idx + 1]);
  }
  return Number(process.env.PORT ?? Bun.env.PORT ?? 3100);
}

function jsonResponse(body: unknown, init?: ResponseInit) {
  return Response.json(body, init);
}

async function readJson(request: Request) {
  if (request.method === "GET" || request.method === "HEAD") {
    return null;
  }
  const text = await request.text();
  if (!text) {
    return null;
  }
  return JSON.parse(text);
}

function hasOwn(obj: unknown, key: string) {
  return !!obj && typeof obj === "object" && Object.prototype.hasOwnProperty.call(obj, key);
}

// Keep this socket bound while fixtures initialize URLs from the assigned port.
const server = Bun.serve({
  port: getPort(),
  fetch: () => new Response("Initializing", { status: 503 }),
});
const PORT = server.port;
console.log(`COMPAT_SERVER_PORT=${PORT}`);
if (process.env.COMPAT_PROXY_CASE) {
  const fixture = JSON.parse(process.env.COMPAT_PROXY_CASE);
  for (const [key, value] of Object.entries(fixture.env) as [string, string][]) {
    process.env[key] = value.replaceAll("{base}", `http://localhost:${PORT}`);
  }
  process.env.COMPAT_PROXY_OPTIONS = JSON.stringify(fixture.options).replaceAll("{base}", `http://localhost:${PORT}`);
}
const identityContextFixture = process.env.COMPAT_PROFILE === "identity-context" ? createIdentityContextFixture(`http://localhost:${PORT}`) : undefined;
const dynamicContextFixture = (["dynamic-context", "dynamic-native", "dynamic-oauth", "id-policy", "organization-metadata"].includes(process.env.COMPAT_PROFILE ?? "") || process.env.COMPAT_PROFILE?.startsWith("dynamic-environment:")) ? createDynamicContextFixture() : undefined;
const dispatchErrorsFixture = process.env.COMPAT_PROFILE === "dispatch-errors" ? createDispatchErrorsFixture(`http://localhost:${PORT}`) : undefined;
const rateLimitFixture = process.env.COMPAT_PROFILE === "rate-limit-options" ? await createRateLimitFixture(`http://localhost:${PORT}`) : undefined;
const oauthPopupFixture = createOAuthPopupFixture(process.env.COMPAT_PROFILE ?? "", `http://localhost:${PORT}`);
const captchaFixture = createCaptchaFixture(process.env.COMPAT_PROFILE ?? "", `http://localhost:${PORT}`);
const jwtFixture = await createJwtFixture(process.env.COMPAT_PROFILE ?? "", `http://localhost:${PORT}`);
const jwtAdapterFixture = process.env.COMPAT_PROFILE === "jwt-adapter" ? createJwtAdapterFixture(`http://localhost:${PORT}`) : null;
const databaseLifecycleFixture = (process.env.COMPAT_PROFILE ?? "").startsWith("database-lifecycle") ? await createStandaloneDatabaseLifecycleFixture(process.env.COMPAT_PROFILE!, `http://localhost:${PORT}`) : null;
const database = new Database(":memory:");
const cryptoFixture = createCryptoFixture(process.env.COMPAT_PROFILE ?? "", database);
const userAdmission = createUserAdmissionFixture(process.env.COMPAT_PROFILE ?? "");
const deviceGenerators = createDeviceGenerators(process.env.COMPAT_PROFILE ?? "", database);
const authLifecycle = createAuthLifecycleFixture(process.env.COMPAT_PROFILE ?? "", database);
const passwordSecurity = createPasswordSecurityFixture();
const identityFixture = createIdentityFixture(database, process.env.COMPAT_PROFILE ?? "");
const apiKeyStorageFixture = createApiKeyStorageFixture();
const secondaryFixture = createSecondaryStorageFixture(process.env.COMPAT_PROFILE ?? "", database);
const cookieVersionFixture = createCookieVersionFixture(process.env.COMPAT_PROFILE ?? "");
const signupEnumeration = signupEnumerationOptions(process.env.COMPAT_PROFILE ?? "");
const passkeyOptions = createPasskeyOptions(process.env.COMPAT_PROFILE ?? "");
const customSessionFixture = createCustomSessionFixture(process.env.COMPAT_PROFILE ?? "");
const otpCallbacks = createOtpCallbacksFixture(process.env.COMPAT_PROFILE ?? "");
const twoFactorConfig = twoFactorOptions(process.env.COMPAT_PROFILE ?? "");
const apiKeyCallbacks = createApiKeyCallbacks(process.env.COMPAT_PROFILE ?? "");
const emailOtpFixture = createEmailOtpFixture(database, process.env.COMPAT_PROFILE ?? "");
const emailOtpNative = createEmailOtpNativeFixture(process.env.COMPAT_PROFILE ?? "");
const emailOtpTransaction = createEmailOtpTransactionFixture(process.env.COMPAT_PROFILE ?? "");
const oauthLinkIdToken = createOAuthLinkIdTokenFixture(process.env.COMPAT_PROFILE ?? "");
const adminOptions = createAdminOptionsFixture(process.env.COMPAT_PROFILE ?? "");
const statelessFixture = (process.env.COMPAT_PROFILE ?? "").startsWith("stateless-")
  ? await createStatelessFixture(process.env.COMPAT_PROFILE ?? "", `http://localhost:${PORT}`)
  : undefined;
const lastLoginFixture = (process.env.COMPAT_PROFILE ?? "").startsWith("last-login-")
  ? await createLastLoginFixture(process.env.COMPAT_PROFILE ?? "", `http://localhost:${PORT}`)
  : undefined;
const apiErrorFixture = ["api-error", "api-error-production"].includes(process.env.COMPAT_PROFILE ?? "")
  ? createApiErrorFixture(`http://localhost:${PORT}`) : null;
const twoFactorAfterFixture = (process.env.COMPAT_PROFILE ?? "").startsWith("two-factor-after-") ? await createTwoFactorAfterFixture(process.env.COMPAT_PROFILE!, `http://localhost:${PORT}`) : undefined;
const phoneNativeFixture = (process.env.COMPAT_PROFILE ?? "").startsWith("phone-native-") ? await createPhoneNativeFixture(process.env.COMPAT_PROFILE!, `http://localhost:${PORT}`) : undefined;
const nativeDispatchFixture = process.env.COMPAT_PROFILE === "native-dispatch" ? createNativeDispatchFixture(`http://localhost:${PORT}`) : undefined;
const requestQueryFixture = ["request-oauth-", "request-otp-", "request-api-key-", "request-two-factor-", "request-admin-", "request-security-", "request-organization-", "request-query-", "request-plugin-", "request-change-email"].some(prefix => (process.env.COMPAT_PROFILE ?? "").startsWith(prefix))
  ? await createRequestQueryFixture(process.env.COMPAT_PROFILE!, `http://localhost:${PORT}`)
  : undefined;
const trailingSlashesFixture = (process.env.COMPAT_PROFILE ?? "").startsWith("trailing-slashes-")
  ? createTrailingSlashesFixture(process.env.COMPAT_PROFILE!, `http://localhost:${PORT}`)
  : undefined;
const usernameFixture = (process.env.COMPAT_PROFILE ?? "").startsWith("username-")
  ? await createUsernameFixture(process.env.COMPAT_PROFILE ?? "", `http://localhost:${PORT}`)
  : undefined;
const oneTapFixture = createOneTapFixture(process.env.COMPAT_PROFILE ?? "");
const organizationCallbacks = createOrganizationCallbacks(process.env.COMPAT_PROFILE ?? "");
const resetPasswordOutbox = new Map<string, { url: string; token: string }>();
const verificationEmailOutbox = new Map<string, { url: string; token: string; metadata?: Record<string, unknown> }>();
const changeEmailOutbox = new Map<string, { newEmail: string; url: string; token: string }>();
const twoFactorOtpOutbox = new Map<string, { otp: string }>();
const twoFactorContext = createTwoFactorContextFixture(twoFactorOtpOutbox);
const invitationEmailOutbox: { id: string; email: string; role: string }[] = [];
let invitationSenderFails = false;
let resetPasswordMode: "capture" | "throw" = "capture";
let oauthRefreshMode: "success" | "error" | "empty" = "success";
type SocialProfile = {
  sub: string;
  email: string;
  name: string;
  image: string | null;
  emailVerified: boolean;
};
const defaultSocialProfile = (): SocialProfile => ({
  sub: "google-account-id",
  email: "google@example.com",
  name: "Google Compat User",
  image: null,
  emailVerified: true,
});
let socialProfile = defaultSocialProfile();
let socialImageProvided = false;
let socialIdTokenValid = true;
type GitHubEmailRecord = {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: "public" | "private" | null;
};
type GitHubProfile = {
  id: string;
  login: string;
  name: string | null;
  email: string | null;
  avatarUrl: string | null;
  emails: GitHubEmailRecord[];
};
const defaultGitHubProfile = (): GitHubProfile => ({
  id: "github-account-id",
  login: "github-compat-user",
  name: null,
  email: null,
  avatarUrl: "https://avatars.githubusercontent.com/u/1?v=4",
  emails: [
    {
      email: "github@example.com",
      primary: true,
      verified: true,
      visibility: "private",
    },
  ],
});
let githubProfile = defaultGitHubProfile();
const oauthServer = Bun.serve({
  port: 0,
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/oauth/authorize" && request.method === "GET") {
      const redirectURI = url.searchParams.get("redirect_uri");
      const state = url.searchParams.get("state");
      if (!redirectURI || !state) {
        return jsonResponse({ message: "redirect_uri and state are required" }, { status: 400 });
      }
      const location = new URL(redirectURI);
      location.searchParams.set("code", "compat-code");
      location.searchParams.set("state", state);
      return Response.redirect(location.toString(), 302);
    }

    if (url.pathname === "/oauth/token" && request.method === "POST") {
      if (oauthRefreshMode === "error") {
        return jsonResponse(
          {
            error: "invalid_grant",
            error_description: "invalid refresh token",
          },
          { status: 400 },
        );
      }

      return jsonResponse({
        access_token: "new-access-token",
        refresh_token: "new-refresh-token",
        id_token: "mock-id-token",
        expires_in: 3600,
        refresh_token_expires_in: 7200,
        scope: "openid,email,profile",
        token_type: "Bearer",
      });
    }

    if (url.pathname === "/oauth/userinfo") {
      return jsonResponse({
        sub: socialProfile.sub,
        email: socialProfile.email,
        name: socialProfile.name,
        picture: socialProfile.image,
        email_verified: socialProfile.emailVerified,
      });
    }

    return jsonResponse({ message: "Not found" }, { status: 404 });
  },
});
const oauthBaseURL = `http://127.0.0.1:${oauthServer.port}`;
const oauthAuthorizationURL = `http://localhost:${PORT}/__test/oauth/authorize`;
const oidcBaseURL = process.env.COMPAT_OIDC_URL;
const oidcProviders = oidcBaseURL ? [
  { providerId: "oidc", discoveryUrl: `${oidcBaseURL}/discovery/valid` },
  { providerId: "oidc-rotation", discoveryUrl: `${oidcBaseURL}/discovery/valid` },
  { providerId: "oidc-no-nonce", discoveryUrl: `${oidcBaseURL}/discovery/valid`, disableIdTokenNonceBinding: true },
  { providerId: "oidc-idp", discoveryUrl: `${oidcBaseURL}/discovery/valid`, allowIdpInitiated: true },
  { providerId: "oidc-basic", discoveryUrl: `${oidcBaseURL}/discovery/valid`, authentication: "basic" as const },
  { providerId: "oidc-public", discoveryUrl: `${oidcBaseURL}/discovery/valid`, clientSecret: undefined, tokenEndpointAuth: { method: "none" as const } },
  { providerId: "oidc-no-signup", discoveryUrl: `${oidcBaseURL}/discovery/valid`, disableSignUp: true },
  {
    providerId: "oidc-email-required", discoveryUrl: `${oidcBaseURL}/discovery/valid`,
    requireEmailVerification: true,
    accountSubject: ({ profile }: { profile: Record<string, unknown> }) => String(profile.external_subject),
    mapProfileToUser: () => ({ name: "Mapped OIDC User", emailVerified: false, image: null }),
  },
  {
    providerId: "oidc-mapped", discoveryUrl: `${oidcBaseURL}/discovery/valid`,
    overrideUserInfo: process.env.COMPAT_PROFILE === "organization-jwt",
    accountSubject: ({ profile }: { profile: Record<string, unknown> }) => String(profile.external_subject),
    mapProfileToUser: (profile: Record<string, unknown>) => ({ name: "Mapped OIDC User", emailVerified: false, image: null, department: "identity", alias: profile.picture ? "picture" : "plain", internalCode: "untrusted", secretNote: "provider-private" }),
  },
  {
    providerId: "oidc-parameters", discoveryUrl: `${oidcBaseURL}/discovery/headers`,
    discoveryHeaders: { "x-compat-discovery": "allowed" },
    pkce: false, prompt: "login", accessType: "offline", responseMode: "query",
    authorizationUrlParams: { prompt: "consent", tenant: "configured", state: "ignored", nonce: "ignored" },
    tokenUrlParams: { audience: "fleet-api" },
  },
  { providerId: "oidc-unavailable", discoveryUrl: `${oidcBaseURL}/discovery/unavailable` },
  { providerId: "oidc-missing-jwks", discoveryUrl: `${oidcBaseURL}/discovery/missing-jwks` },
  { providerId: "oidc-invalid-issuer", discoveryUrl: `${oidcBaseURL}/discovery/invalid-issuer` },
  {
    providerId: "oauth-fallback", discoveryUrl: `${oidcBaseURL}/discovery/unavailable`,
    authorizationUrl: `${oidcBaseURL}/authorize`, tokenUrl: `${oidcBaseURL}/token`,
    userInfoUrl: `${oidcBaseURL}/userinfo`, requireIdTokenVerification: false,
  },
].map((provider) => ({
  clientId: "oidc-client",
  clientSecret: "oidc-secret",
  scopes: ["email", "profile"],
  requireIdTokenVerification: true,
  ...(process.env.COMPAT_PROFILE?.startsWith("oauth-proxy") ? { redirectURI: `https://production.example.com/api/auth/callback/${provider.providerId}` } : {}),
  ...provider,
})) : [];

const originalFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const request = input instanceof Request ? input : new Request(input, init);
  const url = new URL(request.url);
  const oneTapResponse = await oneTapFixture.handle(request);
  if (oneTapResponse) return oneTapResponse;

  if (url.origin === "https://oauth2.googleapis.com" && url.pathname === "/token") {
    if (oauthRefreshMode === "error") {
      return jsonResponse(
        {
          error: "invalid_grant",
          error_description: "invalid refresh token",
        },
        { status: 400 },
      );
    }

    const code = new URLSearchParams(await request.text()).get("code");
    const scope = code === "compat-scope-missing" ? undefined : code === "compat-scope-empty" ? "" :
      code === "compat-scope-array" ? [" \ufeffaudit\ufeff ", " email ", "", 42, "\u0085legacy"] : "openid email profile";
    return jsonResponse({
      access_token: "google-access-token",
      refresh_token: "google-refresh-token",
      id_token: "google-id-token",
      expires_in: 3600,
      refresh_token_expires_in: 7200,
      scope,
      token_type: "Bearer",
    });
  }

  if (url.origin === "https://github.com" && url.pathname === "/login/oauth/access_token") {
    if (oauthRefreshMode === "error") {
      return jsonResponse(
        {
          error: "invalid_grant",
          error_description: "invalid refresh token",
        },
        { status: 400 },
      );
    }

    return jsonResponse({
      access_token: "github-access-token",
      refresh_token: "github-refresh-token",
      expires_in: 3600,
      refresh_token_expires_in: 7200,
      scope: "read:user user:email",
      token_type: "bearer",
    });
  }

  if (url.origin === "https://api.github.com" && url.pathname === "/user") {
    return jsonResponse({
      id: githubProfile.id,
      login: githubProfile.login,
      name: githubProfile.name,
      email: githubProfile.email,
      avatar_url: githubProfile.avatarUrl,
    });
  }

  if (url.origin === "https://api.github.com" && url.pathname === "/user/emails") {
    return jsonResponse(githubProfile.emails);
  }

  return originalFetch(request);
};

const proxyCase = process.env.COMPAT_PROXY_CASE ? JSON.parse(process.env.COMPAT_PROXY_CASE) : {};
const authOptions = {
  secondaryStorage: apiKeyStorageFixture.secondaryStorage,
  verification: { ...(apiKeyStorageFixture.enabled ? { storeInDatabase: true } : {}), ...emailOtpTransaction.verification },
  baseURL: proxyCase.baseURL ?? `http://localhost:${PORT}`,
  trustedOrigins: proxyCase.trustedOrigins ?? [],
  ...oauthPopupFixture.options,
  ...(oauthPopupFixture.hooks ? { databaseHooks: oauthPopupFixture.hooks } : {}),
  basePath: "/api/auth",
  ...(process.env.COMPAT_PROFILE?.startsWith("oauth-proxy") ? { account: {
    ...(process.env.COMPAT_PROFILE === "oauth-proxy-cookie" ? { storeStateStrategy: "cookie" as const } : {}),
    accountLinking: { updateUserInfoOnLink: true },
  } } : {}),
  ...(oauthLinkIdToken.enabled ? { account: oauthLinkIdToken.account, databaseHooks: oauthLinkIdToken.databaseHooks } : {}),
  ...(adminOptions.databaseHooks ? { databaseHooks: adminOptions.databaseHooks } : {}),
  secret: ["compat", "test", "only", "key", "not", "real", "minimum", "32chars"].join("-"),
  database,
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
    minPasswordLength: 8,
    async sendResetPassword({ user, url, token }: { user: { email?: string } | null; url: string; token: string }) {
      if (resetPasswordMode === "throw") {
        throw new Error("compat reset sender failure");
      }
      if (user?.email) {
        resetPasswordOutbox.set(user.email, { url, token });
      }
    },
    ...passwordPolicyOptions(process.env.COMPAT_PROFILE ?? ""),
    ...signupEnumeration?.emailAndPassword,
    ...authLifecycle.emailAndPassword,
    ...passwordSecurity.emailAndPassword(process.env.COMPAT_PROFILE ?? ""),
    ...userAdmission.emailAndPassword,
    ...emailOtpTransaction.emailAndPassword,
  },
  emailVerification: {
    ...(process.env.COMPAT_PROFILE === "otp-callbacks-override" ? { sendOnSignUp: true } : {}),
    autoSignInAfterVerification: process.env.COMPAT_PROFILE === "email-otp-options",
    sendVerificationEmail: ["email-otp-reuse", "otp-callbacks-override"].includes(process.env.COMPAT_PROFILE ?? "") ? undefined : async ({
      user,
      url,
      token,
    }: {
      user: { email?: string } | null;
      url: string;
      token: string;
    }) => {
      if (user?.email) {
        verificationEmailOutbox.set(user.email, { url, token });
      }
    },
  },
  session: authLifecycle.options.session ?? (apiKeyStorageFixture.enabled ? { storeSessionInDatabase: true } : ["user-fields", "organization-cache", "jwt-cache", "organization-jwt"].includes(process.env.COMPAT_PROFILE ?? "") ? {
    cookieCache: { enabled: true, strategy: ["jwt-cache", "organization-jwt"].includes(process.env.COMPAT_PROFILE ?? "") ? "jwt" as const : "compact" as const },
    ...(process.env.COMPAT_PROFILE === "organization-jwt" ? { additionalFields: {
      deviceLabel: { type: "string" as const, required: false },
      internalNote: { type: "string" as const, required: false, input: false, returned: false },
    } } : {}),
  } : undefined),
  user: {
    ...userAdmission.user,
    ...emailOtpTransaction.user,
    ...(oauthLinkIdToken.enabled ? oauthLinkIdToken.user : {}),
    additionalFields: (adminOptions.plugin ? adminOptions.userFields : undefined) ?? (oauthLinkIdToken.enabled ? oauthLinkIdToken.user.additionalFields : undefined) ?? authLifecycle.options.user?.additionalFields ?? signupEnumeration?.userFields ?? cookieVersionFixture.userFields ?? (["user-fields", "organization-jwt"].includes(process.env.COMPAT_PROFILE ?? "") ? userFields : ["organization-callbacks", "organization-custom-team", "two-factor-context"].includes(process.env.COMPAT_PROFILE ?? "") ? { secretNote: { type: "string", required: false, returned: false, defaultValue: "hidden" } } : undefined),
    changeEmail: {
      enabled: true,
      async sendChangeEmailConfirmation({
        user,
        newEmail,
        url,
        token,
      }: {
        user: { email?: string } | null;
        newEmail: string;
        url: string;
        token: string;
      }) {
        if (user?.email) {
          changeEmailOutbox.set(user.email, { newEmail, url, token });
        }
      },
    },
    deleteUser: {
      enabled: true,
      ...authLifecycle.deleteUser,
    },
  },
  rateLimit: {
    enabled: ["device-rate-limit", "device-rate-window"].includes(process.env.COMPAT_PROFILE ?? ""),
  },
  ...captchaFixture.options,
  ...httpBodyOptions(process.env.COMPAT_PROFILE ?? ""),
  socialProviders: {
    github: {
      clientId: "github-client-id",
      clientSecret: "github-client-secret",
      authorizationEndpoint: oauthAuthorizationURL,
    },
    google: {
      hd: process.env.COMPAT_PROFILE === "one-tap-options" ? "example.com" : undefined,
      clientId: "google-client-id",
      clientSecret: "google-client-secret",
      enabled: true,
      authorizationEndpoint: oauthAuthorizationURL,
      async verifyIdToken() {
        return socialIdTokenValid;
      },
      async getUserInfo() {
        return {
          user: {
            id: socialProfile.sub,
            email: socialProfile.email,
            name: socialProfile.name,
            image: process.env.COMPAT_PROFILE?.startsWith("oauth-proxy") && socialImageProvided
              ? socialProfile.image
              : socialProfile.image ?? undefined,
            emailVerified: socialProfile.emailVerified,
          },
          data: {
            sub: socialProfile.sub,
            email: socialProfile.email,
            email_verified: socialProfile.emailVerified,
            name: socialProfile.name,
            picture: socialProfile.image,
          },
        };
      },
      async refreshAccessToken() {
        if (oauthRefreshMode === "error") {
          throw new Error("invalid refresh token");
        }

        return {
          accessToken: oauthRefreshMode === "empty" ? "" : "google-access-token",
          refreshToken: oauthRefreshMode === "empty" ? "" : "google-refresh-token",
          idToken: oauthRefreshMode === "empty" ? "" : "google-id-token",
          accessTokenExpiresAt: new Date(Date.now() + 3600_000),
          refreshTokenExpiresAt: new Date(Date.now() + 7200_000),
          scopes: ["openid", "email", "profile"],
        };
      },
      ...(oauthLinkIdToken.enabled ? oauthLinkIdToken.google : {}),
    },
  },
  plugins: [
    ...captchaFixture.plugins,
    ...oauthPopupFixture.plugins,
    ...userAdmission.plugins,
    ...(process.env.COMPAT_PROFILE?.startsWith("password-security") && process.env.COMPAT_PROFILE !== "password-security-after" ? [passwordSecurity.plugin(process.env.COMPAT_PROFILE)] : []),
    ...jwtFixture.plugins,
    ...mappedPluginExtras,
    ...(process.env.COMPAT_PROFILE?.startsWith("oauth-proxy") ? [oAuthProxy(process.env.COMPAT_PROXY_OPTIONS ? JSON.parse(process.env.COMPAT_PROXY_OPTIONS) : { productionURL: "https://production.example.com", currentURL: `http://localhost:${PORT}` })] : []),
    ...identityFixture.plugins,
    ...tokenRoutePlugins(process.env.COMPAT_PROFILE ?? "", verificationEmailOutbox),
    ...customSessionFixture.plugins,
    ...(["otp-callbacks", "otp-callbacks-override"].includes(process.env.COMPAT_PROFILE ?? "") ? otpCallbacks.plugins : []),
    ...emailOtpNative.plugins,
    ...emailOtpTransaction.plugins,
    ...((process.env.COMPAT_PROFILE?.startsWith("email-otp") && !emailOtpNative.enabled && !emailOtpTransaction.enabled) || process.env.COMPAT_PROFILE === "user-fields" ? [emailOtpFixture.plugin] : []),
    ...(process.env.COMPAT_PROFILE?.startsWith("one-tap") ? [oneTapFixture.plugin] : []),
    ...(process.env.COMPAT_PROFILE === "device-bearer" ? [bearer()] : []),
    adminOptions.plugin ?? admin(),
    apiKey(apiKeyCallbacks.configurations ?? [
      { configId: "default", enableMetadata: true, defaultKeyLength: process.env.COMPAT_PROFILE === "api-key-zero" ? 0 : 64 },
      { configId: "secondary", enableMetadata: true },
      { configId: "session", enableSessionForAPIKeys: true, apiKeyHeaders: ["x-api-key", "x-machine-key"] },
      { configId: "shared-first", enableSessionForAPIKeys: true, apiKeyHeaders: "x-shared-key" },
      { configId: "shared-second", enableSessionForAPIKeys: true, apiKeyHeaders: "x-shared-key" },
      { configId: "organization", references: "organization", enableMetadata: true },
      ...apiKeyStorageFixture.configurations,
    ], { schema: mappedPluginSchema && { apikey: mappedPluginSchema.apikey } }),
    deviceAuthorization({
      schema: mappedPluginSchema && { deviceCode: mappedPluginSchema.deviceCode },
      expiresIn: process.env.COMPAT_PROFILE === "device-rate-window" ? "2s" : "30m",
      generateUserCode: process.env.COMPAT_PROFILE === "device-custom"
        ? () => "custom-code"
        : process.env.COMPAT_PROFILE === "device-collision"
          ? (() => {
              let issued = 0;
              return () => ++issued <= 2 ? "same-code" : issued <= 6 ? "next-code" : "after-code";
            })()
          : undefined,
      ...deviceGenerators.options,
    }),
    organization({
      ...(process.env.COMPAT_PROFILE === "organization-empty-roles" ? { roles: {} } : {}),
      ...(["organization-invitation-options", "organization-invitation-unverified"].includes(process.env.COMPAT_PROFILE ?? "") ? {
        cancelPendingInvitationsOnReInvite: true,
        requireEmailVerificationOnInvitation: process.env.COMPAT_PROFILE === "organization-invitation-options",
        invitationLimit: 1,
      } : {}),
      ...(process.env.COMPAT_PROFILE?.startsWith("organization-") ? {
        teams: { enabled: true, ...(process.env.COMPAT_PROFILE === "organization-limits" ? { defaultTeam: { enabled: false }, maximumTeams: 2, maximumMembersPerTeam: 1, allowRemovingAllTeams: true } : {}) },
        dynamicAccessControl: { enabled: true, ...(process.env.COMPAT_PROFILE === "organization-limits" ? { maximumRolesPerOrganization: 1 } : {}) },
        ...(process.env.COMPAT_PROFILE === "organization-no-ac" ? {} : { ac: createAccessControl(defaultStatements) }),
      } : {}),
      ...organizationCallbacks.options,
      ...organizationFieldOptions(process.env.COMPAT_PROFILE ?? ""),
      ...organizationCoreFieldOptions(process.env.COMPAT_PROFILE ?? ""),
      ...organizationDynamicFieldOptions(process.env.COMPAT_PROFILE ?? ""),
      ...organizationMemberFieldOptions(process.env.COMPAT_PROFILE ?? ""),
      ...organizationNativeJsonOptions(process.env.COMPAT_PROFILE ?? ""),
      async sendInvitationEmail({ id, email, role }) {
        await Promise.resolve();
        if (invitationSenderFails) throw new Error("compat invitation sender failure");
        invitationEmailOutbox.push({ id, email, role });
      },
    }),
    passkey({ schema: mappedPluginSchema && { passkey: mappedPluginSchema.passkey }, ...passkeyOptions.options }),
    twoFactor({
      schema: mappedPluginSchema && { twoFactor: mappedPluginSchema.twoFactor },
      ...twoFactorConfig,
      otpOptions: {
        ...twoFactorConfig.otpOptions,
        async sendOTP({ user, otp }) {
          if (user.email) {
            twoFactorOtpOutbox.set(user.email, { otp });
          }
        },
        ...(process.env.COMPAT_PROFILE === "two-factor-context" ? { sendOTP: twoFactorContext.sendOTP } : {}),
      },
    }),
    username(),
    genericOAuth({
      config: [
        ...oidcProviders,
        ...oauthPopupFixture.providers,
        {
          providerId: "mock",
          endSessionEndpoint: "https://idp.example.test/logout",
          authorizationUrl: oauthAuthorizationURL,
          tokenUrl: `${oauthBaseURL}/oauth/token`,
          userInfoUrl: `${oauthBaseURL}/oauth/userinfo`,
          clientId: "mock-client-id",
          clientSecret: "mock-client-secret",
          scopes: ["openid", "email", "profile"],
          pkce: true,
          async getUserInfo() {
            return {
              id: "mock-account-id",
              email: "mock@example.com",
              name: "Mock OAuth User",
              image: null,
              emailVerified: true,
            };
          },
        },
      ],
    }),
    ...(process.env.COMPAT_PROFILE === "password-security-after" ? [passwordSecurity.plugin(process.env.COMPAT_PROFILE)] : []),
  ],
  ...secondaryFixture.options,
  ...sessionFieldOptions(process.env.COMPAT_PROFILE ?? "", secondaryFixture.options.session),
  ...cookieVersionFixture.options,
  ...cryptoFixture.options,
  ...passkeyOptions.authOptions,
  ...customSessionFixture.options,
} as const;

const { runMigrations } = await getMigrations(authOptions);
await runMigrations();

const auth = betterAuth(authOptions);
const disabledUserPlugins = process.env.COMPAT_PROFILE === "user-fields"
  ? betterAuth({ ...authOptions, plugins: [] }) : undefined;
const hiddenUserFields = process.env.COMPAT_PROFILE === "user-fields"
  ? betterAuth({ ...authOptions, plugins: [], user: { ...authOptions.user, additionalFields: {
    ...userFields, department: { ...userFields.department, returned: false }, alias: { ...userFields.alias, returned: false },
  } } }) : undefined;
const authContext = await auth.$context;
const RESET_MODELS = [
  "deviceCode",
  "passkey",
  "apikey",
  ...(process.env.COMPAT_PROFILE?.startsWith("organization-") ? ["teamMember", "team", "organizationRole"] : []),
  "invitation",
  "member",
  "organization",
  "verification",
  "account",
  "session",
  "user",
] as const;

async function resetDatabaseState() {
  for (const model of RESET_MODELS) {
    if (secondaryFixture.skipResetModel(model)) continue;
    await authContext.adapter.deleteMany({
      model,
      where: [],
    });
  }
}

server.reload({
  async fetch(request) {
    if (process.env.COMPAT_PROFILE === "account-verification-fields") {
      const handled = await routeVerificationDateOutput(request) ?? await routeAccountVerificationFields(request) ?? await routeAccountHttpOutput(request);
      if (handled) return handled;
      const path = new URL(request.url).pathname;
      if (path === "/__test/reset-state") return Response.json({ success: true });
      if (["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
      return new Response(null, {status: 404});
    }
    if (apiErrorFixture) return apiErrorFixture.handle(request);
    if (twoFactorAfterFixture) return twoFactorAfterFixture.handle(request);
    if (phoneNativeFixture) return phoneNativeFixture.handle(request);
    if (nativeDispatchFixture) return nativeDispatchFixture.handle(request);
    if (requestQueryFixture) return requestQueryFixture.handle(request);
    if (trailingSlashesFixture) return trailingSlashesFixture.handle(request);
    if (usernameFixture) return usernameFixture.handle(request);
    if (jwtAdapterFixture) return jwtAdapterFixture.handle(request);
    if (databaseLifecycleFixture) return databaseLifecycleFixture.handle(request);
    if (identityContextFixture) return identityContextFixture.handle(request);
    if (process.env.COMPAT_PROFILE === "openapi") {
      const path = new URL(request.url).pathname;
      if (request.method === "POST" && path === "/__test/openapi") return Response.json(await runOpenApi(await request.json()));
      if (request.method === "POST" && path === "/__test/reset-state") return Response.json({ success: true });
      if (request.method === "GET" && ["/health", "/__health"].includes(path)) return Response.json({ status: "ok" });
      return new Response(null, { status: 404 });
    }
    if (dynamicContextFixture) return dynamicContextFixture.handle(request);
    if (dispatchErrorsFixture) return dispatchErrorsFixture.handle(request);
    if (rateLimitFixture) return rateLimitFixture.handle(request);
    if (lastLoginFixture) return lastLoginFixture.handle(request);
    if (statelessFixture) return statelessFixture.handle(request);
    try {
      const url = new URL(request.url);

      if (disabledUserPlugins && url.pathname === "/__test/disabled/get-session") {
        url.pathname = "/api/auth/get-session";
        return disabledUserPlugins.handler(new Request(url, request));
      }
      if (hiddenUserFields && url.pathname === "/__test/hidden/get-session") {
        url.pathname = "/api/auth/get-session";
        return hiddenUserFields.handler(new Request(url, request));
      }

      const lifecycleResponse = await authLifecycle.route(request, auth);
      const captchaResponse = await captchaFixture.handle(request, auth);
      if (captchaResponse) return captchaResponse;
      const cryptoResponse = await cryptoFixture.handle(request, auth);
      if (cryptoResponse) return cryptoResponse;
      const admissionResponse = await userAdmission.route(request, auth);
      if (admissionResponse) return admissionResponse;
      const emailOtpNativeResponse = await emailOtpNative.route(request, auth);
      if (emailOtpNativeResponse) return emailOtpNativeResponse;
      const emailOtpTransactionResponse = await emailOtpTransaction.route(request, auth);
      if (emailOtpTransactionResponse) return emailOtpTransactionResponse;
      const oauthLinkIdTokenResponse = await oauthLinkIdToken.route(request, auth);
      if (oauthLinkIdTokenResponse) return oauthLinkIdTokenResponse;
      const oauthPopupResponse = await oauthPopupFixture.route(request, auth);
      if (oauthPopupResponse) return oauthPopupResponse;
      const adminOptionsResponse = await adminOptions.route(request, auth);
      if (adminOptionsResponse) return adminOptionsResponse;
      const deviceGeneratorsResponse = await deviceGenerators.handle(request);
      if (deviceGeneratorsResponse) return deviceGeneratorsResponse;
      if (lifecycleResponse) return lifecycleResponse;
      const passwordSecurityResponse = await passwordSecurity.handle(request, auth);
      if (passwordSecurityResponse) return passwordSecurityResponse;
      const secondaryResponse = await secondaryFixture.route(request, auth);
      if (secondaryResponse) return secondaryResponse;
      const cookieVersionResponse = await cookieVersionFixture.route(request);
      if (cookieVersionResponse) return cookieVersionResponse;
      const passkeyOptionsResponse = await passkeyOptions.route(request, auth);
      if (passkeyOptionsResponse) return passkeyOptionsResponse;
      const customSessionResponse = await customSessionFixture.route(request);
      if (customSessionResponse) return customSessionResponse;
      if (url.pathname === "/__test/two-factor-options" && request.method === "GET") {
        return jsonResponse(twoFactorOptionsState(database, url.searchParams.get("userId")!));
      }
      if (url.pathname === "/__test/generate-totp" && request.method === "POST") {
        return jsonResponse(await auth.api.generateTOTP({ body: await readJson(request) }));
      }
      const storageResponse = await apiKeyStorageFixture.handle(request, auth);
      const callbacksResponse = await apiKeyCallbacks.route(request, auth);
      if (callbacksResponse) return callbacksResponse;
      if (storageResponse) return storageResponse;
      const organizationResponse = await organizationCallbacks.route(request);
      if (organizationResponse) return organizationResponse;
      if (url.pathname === "/__test/organization-add-member" && request.method === "POST") {
        return auth.api.addMember({ body: await readJson(request), headers: request.headers, asResponse: true });
      }
      const identityResponse = await identityFixture.handle(request);
      const jwtResponse = await jwtFixture.handle(request, auth);
      if (jwtResponse) return jwtResponse;
      if (identityResponse) return identityResponse;
      const emailOtpResponse = await emailOtpFixture.handle(request);
      if (emailOtpResponse) return emailOtpResponse;
      const otpCallbacksResponse = await otpCallbacks.handle(request);
      if (otpCallbacksResponse) return otpCallbacksResponse;
      const twoFactorContextResponse = await twoFactorContext.handle(request);
      if (twoFactorContextResponse) return twoFactorContextResponse;
      const oneTapResponse = await oneTapFixture.handle(request);
      if (oneTapResponse) return oneTapResponse;

      if (url.pathname === "/__health") {
        return jsonResponse({ ok: true });
      }
      if (url.pathname === "/__test/oauth-proxy/stats") {
        return jsonResponse({
          users: (database.query('SELECT COUNT(*) AS count FROM "user"').get() as { count: number }).count,
          sessions: (database.query('SELECT COUNT(*) AS count FROM "session"').get() as { count: number }).count,
        });
      }

      if (url.pathname === "/__test/oauth/authorize" && request.method === "GET") {
        return originalFetch(`${oauthBaseURL}/oauth/authorize${url.search}`, { redirect: "manual" });
      }

      if (url.pathname === "/__test/api-key/create" && request.method === "POST") {
        return jsonResponse(await auth.api.createApiKey({ body: await readJson(request) }));
      }
      if (url.pathname === "/__test/api-key/update" && request.method === "POST") {
        return jsonResponse(await auth.api.updateApiKey({ body: await readJson(request) }));
      }
      if (url.pathname === "/__test/api-key/verify" && request.method === "POST") {
        return jsonResponse(await auth.api.verifyApiKey({ body: await readJson(request) }));
      }

      if (url.pathname === "/__test/reset-state" && request.method === "POST") {
        await resetDatabaseState();
        identityFixture.reset();
        organizationCallbacks.reset();
        emailOtpFixture.reset();
        emailOtpNative.reset();
        emailOtpTransaction.reset();
        oauthLinkIdToken.reset();
        adminOptions.reset();
        oauthPopupFixture.reset();
        otpCallbacks.reset();
        authLifecycle.reset();
        captchaFixture.reset();
        userAdmission.reset();
        deviceGenerators.reset();
        passwordSecurity.reset();
        twoFactorContext.reset();
        apiKeyStorageFixture.reset();
        secondaryFixture.reset();
        cookieVersionFixture.reset();
        passkeyOptions.reset();
        customSessionFixture.reset();
        apiKeyCallbacks.reset();
        oneTapFixture.reset();
        resetPasswordOutbox.clear();
        verificationEmailOutbox.clear();
        changeEmailOutbox.clear();
        twoFactorOtpOutbox.clear();
        invitationEmailOutbox.length = 0;
        invitationSenderFails = false;
        resetPasswordMode = "capture";
        oauthRefreshMode = "success";
        socialProfile = defaultSocialProfile();
        socialImageProvided = false;
        socialIdTokenValid = true;
        githubProfile = defaultGitHubProfile();
        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/invitation-emails" && request.method === "GET") {
        return jsonResponse(invitationEmailOutbox.filter((record) => record.email === url.searchParams.get("email")));
      }

      if (url.pathname === "/__test/invitation-sender-mode" && request.method === "POST") {
        const body = await readJson(request) as { fail: boolean };
        invitationSenderFails = body.fail;
        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/shorten-invitation-expiry" && request.method === "POST") {
        const body = await readJson(request) as { id: string };
        const expiresAt = new Date(Date.now() + 3600_000);
        await authContext.adapter.update({
          model: "invitation",
          where: [{ field: "id", value: body.id }],
          update: { expiresAt },
        });
        return jsonResponse({ expiresAt });
      }

      if (url.pathname === "/__test/verification-email" && request.method === "GET") {
        const email = url.searchParams.get("email");
        const record = email ? verificationEmailOutbox.get(email) ?? null : null;
        return record
          ? jsonResponse(record)
          : jsonResponse({ message: "Not found" }, { status: 404 });
      }

      if (url.pathname === "/__test/change-email-confirmation" && request.method === "GET") {
        const email = url.searchParams.get("email");
        const record = email ? changeEmailOutbox.get(email) ?? null : null;
        return record
          ? jsonResponse(record)
          : jsonResponse({ message: "Not found" }, { status: 404 });
      }

      if (url.pathname === "/__test/reset-password-token" && request.method === "GET") {
        const email = url.searchParams.get("email");
        const record = email ? resetPasswordOutbox.get(email) ?? null : null;
        return record
          ? jsonResponse(record)
          : jsonResponse({ message: "Not found" }, { status: 404 });
      }

      if (url.pathname === "/__test/two-factor-otp" && request.method === "GET") {
        const email = url.searchParams.get("email");
        const record = email ? twoFactorOtpOutbox.get(email) ?? null : null;
        return record
          ? jsonResponse(record)
          : jsonResponse({ message: "Not found" }, { status: 404 });
      }

      if (url.pathname === "/__test/view-backup-codes" && request.method === "GET") {
        const userId = url.searchParams.get("userId");
        if (!userId) {
          return jsonResponse({ message: "userId is required" }, { status: 400 });
        }

        try {
          const result = await auth.api.viewBackupCodes({
            body: {
              userId,
            },
          });
          return jsonResponse(result);
        } catch (error) {
          const message = error instanceof Error ? error.message : "Unknown error";
          return jsonResponse({ message }, { status: 500 });
        }
      }

      if (url.pathname === "/__test/set-reset-password-mode" && request.method === "POST") {
        const body = (await readJson(request)) as { mode?: string } | null;
        resetPasswordMode = body?.mode === "throw" ? "throw" : "capture";
        return jsonResponse({ status: true, mode: resetPasswordMode });
      }

      if (url.pathname === "/__test/seed-reset-password-token" && request.method === "POST") {
        const body = (await readJson(request)) as {
          email?: string;
          token?: string;
          expiresAt?: string;
        } | null;
        const email = body?.email;
        const token = body?.token;
        const expiresAt = body?.expiresAt;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user || !token || !expiresAt) {
          return jsonResponse(
            { message: "email, token, and expiresAt are required" },
            { status: 400 },
          );
        }

        await authContext.internalAdapter.createVerificationValue({
          value: user.user.id,
          identifier: `reset-password:${token}`,
          expiresAt: new Date(expiresAt),
        });

        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/seed-delete-user-token" && request.method === "POST") {
        const body = (await readJson(request)) as {
          email?: string;
          token?: string;
          expiresAt?: string;
        } | null;
        const email = body?.email;
        const token = body?.token;
        const expiresAt = body?.expiresAt;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user || !token || !expiresAt) {
          return jsonResponse(
            { message: "email, token, and expiresAt are required" },
            { status: 400 },
          );
        }

        await authContext.internalAdapter.createVerificationValue({
          value: user.user.id,
          identifier: `delete-account-${token}`,
          expiresAt: new Date(expiresAt),
        });

        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/remove-credential-account" && request.method === "POST") {
        const body = (await readJson(request)) as { email?: string } | null;
        const email = body?.email;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user) {
          return jsonResponse({ message: "User not found" }, { status: 404 });
        }

        for (const account of user.accounts ?? []) {
          if (account.providerId === "credential") {
            await authContext.internalAdapter.deleteAccount(account.id);
          }
        }

        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/promote-admin" && request.method === "POST") {
        const body = (await readJson(request)) as { email?: string } | null;
        const email = body?.email;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user) {
          return jsonResponse({ message: "User not found" }, { status: 404 });
        }

        await authContext.internalAdapter.updateUser(user.user.id, {
          role: "admin",
        });

        return jsonResponse({ status: true });
      }

      if (url.pathname === "/__test/set-oauth-refresh-mode" && request.method === "POST") {
        const body = (await readJson(request)) as { mode?: string } | null;
        oauthRefreshMode = body?.mode === "error" ? "error" : body?.mode === "empty" ? "empty" : "success";
        return jsonResponse({ status: true, mode: oauthRefreshMode });
      }

      if (url.pathname === "/__test/set-social-profile" && request.method === "POST") {
        const body = (await readJson(request)) as Partial<SocialProfile> & {
          idTokenValid?: boolean;
        } | null;
        if (body && hasOwn(body, "image")) socialImageProvided = true;
        socialProfile = {
          ...socialProfile,
          ...(body?.sub ? { sub: body.sub } : {}),
          ...(body?.email ? { email: body.email } : {}),
          ...(body?.name ? { name: body.name } : {}),
          ...(body && hasOwn(body, "image") ? { image: body.image ?? null } : {}),
          ...(typeof body?.emailVerified === "boolean"
            ? { emailVerified: body.emailVerified }
            : {}),
        };
        if (typeof body?.idTokenValid === "boolean") {
          socialIdTokenValid = body.idTokenValid;
        }
        return jsonResponse({ status: true, profile: socialProfile, idTokenValid: socialIdTokenValid });
      }

      if (url.pathname === "/__test/set-github-profile" && request.method === "POST") {
        const body = (await readJson(request)) as Partial<GitHubProfile> | null;
        githubProfile = {
          ...githubProfile,
          ...(body?.id ? { id: body.id } : {}),
          ...(body?.login ? { login: body.login } : {}),
          ...(body && hasOwn(body, "name") ? { name: body.name ?? null } : {}),
          ...(body && hasOwn(body, "email") ? { email: body.email ?? null } : {}),
          ...(body && hasOwn(body, "avatarUrl") ? { avatarUrl: body.avatarUrl ?? null } : {}),
          ...(Array.isArray(body?.emails) ? { emails: body.emails } : {}),
        };
        return jsonResponse({ status: true, profile: githubProfile });
      }

      if (url.pathname === "/__test/seed-oauth-account" && request.method === "POST") {
        const body = (await readJson(request)) as {
          email?: string;
          providerId?: string;
          accountId?: string;
          accessToken?: string | null;
          refreshToken?: string | null;
          idToken?: string | null;
          accessTokenExpiresAt?: string | null;
          refreshTokenExpiresAt?: string | null;
          scope?: string | null;
        } | null;
        const email = body?.email;
        const user = email
          ? await authContext.internalAdapter.findUserByEmail(email, {
              includeAccounts: true,
            })
          : null;

        if (!user?.user) {
          return jsonResponse({ message: "User not found" }, { status: 404 });
        }

        const providerId = body?.providerId ?? "mock";
        const accountId = body?.accountId ?? "mock-account-id";
        const existing = user.accounts?.find(
          (account) => account.providerId === providerId && account.accountId === accountId,
        );

        const accountData = {
          accessToken: hasOwn(body, "accessToken") ? body?.accessToken ?? null : "stale-access-token",
          refreshToken: hasOwn(body, "refreshToken") ? body?.refreshToken ?? null : "seed-refresh-token",
          idToken: hasOwn(body, "idToken") ? body?.idToken ?? null : "seed-id-token",
          accessTokenExpiresAt: hasOwn(body, "accessTokenExpiresAt")
            ? body?.accessTokenExpiresAt
              ? new Date(body.accessTokenExpiresAt)
              : null
            : new Date(Date.now() - 60_000),
          refreshTokenExpiresAt: hasOwn(body, "refreshTokenExpiresAt")
            ? body?.refreshTokenExpiresAt
              ? new Date(body.refreshTokenExpiresAt)
              : null
            : null,
          scope: hasOwn(body, "scope") ? body?.scope ?? null : "openid,email,profile",
        };

        let localAccountId = existing?.id;
        if (existing?.id) {
          await authContext.internalAdapter.updateAccount(existing.id, accountData);
        } else {
          const account = await authContext.internalAdapter.createAccount({
            userId: user.user.id,
            providerId,
            accountId,
            ...accountData,
          });
          localAccountId = account.id;
        }

        return jsonResponse({ status: true, accountId: localAccountId });
      }

      return auth.handler(request);
    } catch (error) {
      console.error("[reference-server] Error:", error);
      return jsonResponse({ message: "Internal server error" }, { status: 500 });
    }
  },
});

console.log(`[reference-server] Listening on http://localhost:${PORT}`);
console.log("READY");

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    server.stop(true);
    oauthServer.stop(true);
    process.exit(0);
  });
}
