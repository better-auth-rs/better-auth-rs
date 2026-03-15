export type RawDiffAllowance = {
  scenario: RegExp;
  path: RegExp;
  reason: string;
};

export const RAW_DIFF_ALLOWLIST: RawDiffAllowance[] = [
  {
    scenario: /sign up with valid credentials returns user and token/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /sign up with duplicate email returns error/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /sign in with valid credentials returns user and token/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /sign in with wrong password returns error/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /get session after sign-in returns session and user/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /sign out after sign-in invalidates session/i,
    path: /responseCookies\.better-auth\.(session_token|session_data|dont_remember)\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /sign out without auth still succeeds/i,
    path: /responseCookies\.better-auth\.(session_token|session_data|dont_remember)\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /get access token .*refresh failure/i,
    path: /responseBodyShape\.cause/,
    reason: "error cause is currently client-inert for better-auth/client",
  },
  {
    scenario: /get access token returns stored unexpired token/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /get access token refreshes expired token/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /refresh token returns a fresh token set/i,
    path: /responseBodyShape\.refreshTokenExpiresAt/,
    reason: "extra expiry field is currently client-inert for better-auth/client",
  },
  {
    scenario: /refresh token returns a fresh token set/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /refresh token surfaces provider refresh failure/i,
    path: /responseBodyShape\.cause/,
    reason: "error cause is currently client-inert for better-auth/client",
  },
  {
    scenario: /refresh token surfaces provider refresh failure/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /list sessions and revoke a session through the SDK/i,
    path: /responseCookies\.better-auth\.(session_token|session_data|dont_remember)(\.maxAge)?/,
    reason: "logout cookie transport drift is currently client-inert",
  },
  {
    scenario: /revoke sessions logs out all active clients/i,
    path: /responseCookies\.better-auth\.(session_token|session_data|dont_remember)(\.maxAge)?/,
    reason: "logout cookie transport drift is currently client-inert",
  },
  {
    scenario: /request password reset .*credentials/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /request password reset masks sender failure/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /reset password token cannot be reused/i,
    path: /responseCookies\.better-auth\.session_token\.maxAge/,
    reason: "cookie max-age drift is currently client-inert",
  },
  {
    scenario: /revoke other sessions keeps the caller alive/i,
    path: /responseCookies\.better-auth\.(session_token|session_data|dont_remember)(\.maxAge)?/,
    reason: "logout cookie transport drift is currently client-inert",
  },
  {
    scenario: /change password with revokeOtherSessions invalidates the other client/i,
    path: /responseCookies\.better-auth\.(session_token|session_data|dont_remember)(\.maxAge)?/,
    reason: "logout cookie transport drift is currently client-inert",
  },
];
