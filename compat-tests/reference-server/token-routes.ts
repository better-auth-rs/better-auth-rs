import { anonymous, jwt, magicLink, multiSession, oneTimeToken, phoneNumber } from "better-auth/plugins";

export function tokenRoutePlugins(profile: string, outbox: Map<string, { url: string; token: string; metadata?: Record<string, unknown> }>) {
  switch (profile) {
    case "jwt":
      return [jwt()];
    case "jwt-rs256":
      return [jwt({ jwks: { keyPairConfig: { alg: "RS256" } } })];
    case "jwt-es256":
      return [jwt({ jwks: { keyPairConfig: { alg: "ES256" } } })];
    case "user-fields":
    case "jwt-identity":
      return [jwt(), anonymous(), phoneNumber({ async sendOTP() { throw new Error("JWT claim test does not deliver phone OTPs"); } })];
    case "magic-link":
    case "magic-link-disabled":
      return [magicLink({
        disableSignUp: profile === "magic-link-disabled",
        storeToken: profile === "magic-link-disabled" ? "hashed" : "plain",
        async sendMagicLink({ email, url, token, metadata }) { outbox.set(email, { url, token, metadata }); },
      })];
    case "one-time-token":
    case "one-time-token-options":
      return [oneTimeToken({
        storeToken: profile === "one-time-token-options" ? "hashed" : "plain",
        disableClientRequest: profile === "one-time-token-options",
        setOttHeaderOnNewSession: profile === "one-time-token-options",
        disableSetSessionCookie: profile === "one-time-token-options",
      })];
    case "multi-session":
    case "multi-session-limit":
      return [multiSession({ maximumSessions: profile === "multi-session-limit" ? 2 : 5 })];
    default:
      return [];
  }
}
