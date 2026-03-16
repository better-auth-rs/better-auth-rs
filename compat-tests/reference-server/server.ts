#!/usr/bin/env bun

import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

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

const PORT = getPort();
const database = new Database(":memory:");
const resetPasswordOutbox = new Map<string, { url: string; token: string }>();
const verificationEmailOutbox = new Map<string, { url: string; token: string }>();
const changeEmailOutbox = new Map<string, { newEmail: string; url: string; token: string }>();
let resetPasswordMode: "capture" | "throw" = "capture";
let oauthRefreshMode: "success" | "error" = "success";
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
let socialIdTokenValid = true;
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
        id_token: "google-id-token",
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

const originalFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const request = input instanceof Request ? input : new Request(input, init);
  const url = new URL(request.url);

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

    return jsonResponse({
      access_token: "google-access-token",
      refresh_token: "google-refresh-token",
      id_token: "google-id-token",
      expires_in: 3600,
      refresh_token_expires_in: 7200,
      scope: "openid email profile",
      token_type: "Bearer",
    });
  }

  return originalFetch(request);
};

const authOptions = {
  baseURL: `http://localhost:${PORT}`,
  basePath: "/api/auth",
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
  },
  emailVerification: {
    async sendVerificationEmail({
      user,
      url,
      token,
    }: {
      user: { email?: string } | null;
      url: string;
      token: string;
    }) {
      if (user?.email) {
        verificationEmailOutbox.set(user.email, { url, token });
      }
    },
  },
  user: {
    changeEmail: {
      enabled: true,
      async sendChangeEmailVerification({
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
    },
  },
  rateLimit: {
    enabled: false,
  },
  socialProviders: {
    google: {
      clientId: "google-client-id",
      clientSecret: "google-client-secret",
      enabled: true,
      authorizationEndpoint: `${oauthBaseURL}/oauth/authorize`,
      async verifyIdToken() {
        return socialIdTokenValid;
      },
      async getUserInfo() {
        return {
          user: {
            id: socialProfile.sub,
            email: socialProfile.email,
            name: socialProfile.name,
            image: socialProfile.image ?? undefined,
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
          accessToken: "google-access-token",
          refreshToken: "google-refresh-token",
          idToken: "google-id-token",
          accessTokenExpiresAt: new Date(Date.now() + 3600_000),
          refreshTokenExpiresAt: new Date(Date.now() + 7200_000),
          scopes: ["openid", "email", "profile"],
        };
      },
    },
  },
  plugins: [
    genericOAuth({
      config: [
        {
          providerId: "mock",
          authorizationUrl: `${oauthBaseURL}/oauth/authorize`,
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
  ],
} as const;

const { runMigrations } = await getMigrations(authOptions);
await runMigrations();

const auth = betterAuth(authOptions);
const authContext = await auth.$context;

const server = Bun.serve({
  port: PORT,
  async fetch(request) {
    try {
      const url = new URL(request.url);

      if (url.pathname === "/__health") {
        return jsonResponse({ ok: true });
      }

      if (url.pathname === "/__test/reset-state" && request.method === "POST") {
        resetPasswordOutbox.clear();
        verificationEmailOutbox.clear();
        changeEmailOutbox.clear();
        resetPasswordMode = "capture";
        oauthRefreshMode = "success";
        socialProfile = defaultSocialProfile();
        socialIdTokenValid = true;
        return jsonResponse({ status: true });
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

      if (url.pathname === "/__test/set-oauth-refresh-mode" && request.method === "POST") {
        const body = (await readJson(request)) as { mode?: string } | null;
        oauthRefreshMode = body?.mode === "error" ? "error" : "success";
        return jsonResponse({ status: true, mode: oauthRefreshMode });
      }

      if (url.pathname === "/__test/set-social-profile" && request.method === "POST") {
        const body = (await readJson(request)) as Partial<SocialProfile> & {
          idTokenValid?: boolean;
        } | null;
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

        if (existing?.id) {
          await authContext.internalAdapter.updateAccount(existing.id, accountData);
        } else {
          await authContext.internalAdapter.createAccount({
            userId: user.user.id,
            providerId,
            accountId,
            ...accountData,
          });
        }

        return jsonResponse({ status: true });
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
