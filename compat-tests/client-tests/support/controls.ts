export type ResetPasswordMode = "capture" | "throw";
export type OAuthRefreshMode = "success" | "error";

export type SocialProfile = {
  sub?: string;
  email?: string;
  name?: string;
  image?: string | null;
  emailVerified?: boolean;
  idTokenValid?: boolean;
};

export type GitHubEmailRecord = {
  email: string;
  primary?: boolean;
  verified?: boolean;
  visibility?: "public" | "private" | null;
};

export type GitHubProfile = {
  id?: string;
  login?: string;
  name?: string | null;
  email?: string | null;
  avatarUrl?: string | null;
  emails?: GitHubEmailRecord[];
};

async function postControl(baseURL: string, path: string, body: unknown) {
  const response = await fetch(`${baseURL}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      connection: "close",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${path} failed for ${baseURL}: ${response.status} ${text}`);
  }

  return response.json().catch(() => null);
}

async function getControl(baseURL: string, path: string, params: Record<string, string>) {
  const url = new URL(path, baseURL);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }

  const response = await fetch(url, {
    headers: {
      connection: "close",
    },
  });

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${path} failed for ${baseURL}: ${response.status} ${text}`);
  }

  return response.json().catch(() => null);
}

export async function resetServerState(baseURL: string) {
  return postControl(baseURL, "/__test/reset-state", {});
}

export async function setResetPasswordMode(baseURL: string, mode: ResetPasswordMode) {
  return postControl(baseURL, "/__test/set-reset-password-mode", { mode });
}

export async function seedResetPasswordToken(
  baseURL: string,
  {
    email,
    token,
    expiresAt,
  }: {
    email: string;
    token: string;
    expiresAt: string;
  },
) {
  return postControl(baseURL, "/__test/seed-reset-password-token", {
    email,
    token,
    expiresAt,
  });
}

export async function readVerificationEmail(
  baseURL: string,
  { email }: { email: string },
) {
  return getControl(baseURL, "/__test/verification-email", { email });
}

export async function readTwoFactorOtp(
  baseURL: string,
  { email }: { email: string },
) {
  return getControl(baseURL, "/__test/two-factor-otp", { email });
}

export async function readChangeEmailConfirmation(
  baseURL: string,
  { email }: { email: string },
) {
  return getControl(baseURL, "/__test/change-email-confirmation", { email });
}

export async function seedDeleteUserToken(
  baseURL: string,
  {
    email,
    token,
    expiresAt,
  }: {
    email: string;
    token: string;
    expiresAt: string;
  },
) {
  return postControl(baseURL, "/__test/seed-delete-user-token", {
    email,
    token,
    expiresAt,
  });
}

export async function removeCredentialAccount(
  baseURL: string,
  { email }: { email: string },
) {
  return postControl(baseURL, "/__test/remove-credential-account", {
    email,
  });
}

export async function promoteAdmin(
  baseURL: string,
  { email }: { email: string },
) {
  return postControl(baseURL, "/__test/promote-admin", {
    email,
  });
}

export async function setOAuthRefreshMode(baseURL: string, mode: OAuthRefreshMode) {
  return postControl(baseURL, "/__test/set-oauth-refresh-mode", { mode });
}

export async function setSocialProfile(baseURL: string, profile: SocialProfile) {
  return postControl(baseURL, "/__test/set-social-profile", profile);
}

export async function setGitHubProfile(baseURL: string, profile: GitHubProfile) {
  return postControl(baseURL, "/__test/set-github-profile", profile);
}

export async function seedOAuthAccount(
  baseURL: string,
  {
    email,
    providerId = "mock",
    accountId = crypto.randomUUID(),
    accessToken = "stale-access-token",
    refreshToken = "seed-refresh-token",
    idToken = "seed-id-token",
    accessTokenExpiresAt = "2000-01-01T00:00:00Z",
    refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
    scope = "openid,email,profile",
  }: {
    email: string;
    providerId?: string;
    accountId?: string;
    accessToken?: string | null;
    refreshToken?: string | null;
    idToken?: string | null;
    accessTokenExpiresAt?: string | null;
    refreshTokenExpiresAt?: string | null;
    scope?: string | null;
  },
) {
  await postControl(baseURL, "/__test/seed-oauth-account", {
    email,
    providerId,
    accountId,
    accessToken,
    refreshToken,
    idToken,
    accessTokenExpiresAt,
    refreshTokenExpiresAt,
    scope,
  });

  return accountId;
}
