import { expect } from "bun:test";
import { SignJWT } from "jose";
import { compatScenario } from "../../../support/scenario";
import { callback, invalid, issuer, verifyLocalEmail } from "./helpers";

compatScenario("One Tap verifies Google RS256 tokens and authenticates the issued session", async (ctx) => {
  const email = ctx.uniqueEmail("one-tap");
  const sign = await issuer(ctx, email.toUpperCase());
  const first = await callback(ctx, await sign({ email_verified: "true" }));
  expect(first.status).toBe(200);
  expect(first.body).toMatchObject({ user: { email, emailVerified: true, name: "One Tap User", image: "https://example.com/avatar.png" } });
  const session = await ctx.actor().client.getSession();
  expect(session.data?.user.id).toBe((first.body as any).user.id);
  const again = await callback(ctx, await sign({ iss: "accounts.google.com", exp: undefined, iat: Math.floor(Date.now() / 1000) - 0.5 }, { kid: "", crit: ["b64"], b64: true }));
  expect(again.status).toBe(200);
  expect((again.body as any).user.id).toBe((first.body as any).user.id);
  const accounts = await ctx.actor().client.listAccounts();
  expect(accounts.error).toBeNull();
  expect(accounts.data).toHaveLength(1);
  expect(accounts.data?.[0].providerId).toBe("google");
  return { first, session, again, accounts };
});

compatScenario("One Tap rejects incorrect signatures, issuer, audience, lifetime, and token claims", async (ctx) => {
  const sign = await issuer(ctx, ctx.uniqueEmail("one-tap-invalid"));
  const now = Math.floor(Date.now() / 1000);
  const cases = [
    { iss: "https://attacker.example.com" }, { aud: "other-client" }, { iss: undefined }, { aud: undefined }, { iss: ["accounts.google.com"] },
    { exp: now - 1 }, { iat: now - 3601 }, { iat: now + 60 },
    { iat: undefined }, { iat: "123" }, { exp: "123" }, { exp: null }, { nbf: now + 60 }, { nbf: null }, { sub: undefined }, { sub: 123 },
  ];
  const invalidClaims = [];
  for (const claims of cases) { const response = await callback(ctx, await sign(claims)); invalid(response); invalidClaims.push(response); }
  const wrongKid = await callback(ctx, await sign({}, { kid: "unknown-key" }));
  invalid(wrongKid);
  const criticalHeader = await callback(ctx, await sign({}, { crit: ["fixture"], fixture: "unsupported" }));
  invalid(criticalHeader);
  const jwt = await sign();
  const parts = jwt.split("."); parts[2] = `${parts[2][0] === "A" ? "B" : "A"}${parts[2].slice(1)}`;
  const tampered = await callback(ctx, parts.join("."));
  invalid(tampered);
  const wrongAlgorithm = await callback(ctx, await new SignJWT({ sub: "attacker", email: "attacker@example.com" }).setProtectedHeader({ alg: "HS256" }).sign(new Uint8Array(32)));
  invalid(wrongAlgorithm);
  const missingEmail = await callback(ctx, await sign({ email: undefined }));
  expect(missingEmail.status).toBe(400);
  expect(missingEmail.body).toEqual({ message: "Email not available in token" });
  const session = await ctx.actor().client.getSession();
  expect(session.data).toBeNull();
  const invalidBody = await ctx.rawRequest({ path: "/api/auth/one-tap/callback", method: "POST", json: { idToken: 123, callbackURL: false } });
  expect(invalidBody.status).toBe(400);
  expect(invalidBody.body).toEqual({ code: "VALIDATION_ERROR", message: "[body.idToken] Invalid input: expected string, received number; [body.callbackURL] Invalid input: expected string, received boolean" });
  return { invalidClaims, wrongKid, criticalHeader, tampered, wrongAlgorithm, missingEmail, invalidBody, session };
});

compatScenario("One Tap links a verified Google identity to the existing email owner", async (ctx) => {
  const email = ctx.uniqueEmail("one-tap-link");
  const signup = await ctx.actor().client.signUp.email({ email, password: "Password123!", name: "Existing Owner" });
  expect(signup.error).toBeNull();
  const sign = await issuer(ctx, email);
  const unverified = await callback(ctx, await sign());
  expect(unverified.status).toBe(401);
  expect(unverified.body).toEqual({ message: "account not linked" });
  const verified = await verifyLocalEmail(ctx, email);
  const linked = await callback(ctx, await sign());
  expect(linked.status).toBe(200);
  expect((linked.body as any).user.id).toBe(signup.data?.user.id);
  const accounts = await ctx.actor().client.listAccounts();
  expect(accounts.error).toBeNull();
  expect(accounts.data?.map(account => account.providerId).sort()).toEqual(["credential", "google"]);
  const untrustedRedirect = await callback(ctx, await sign(), { callbackURL: "https://attacker.example.com/redirect" });
  expect(untrustedRedirect.status).toBe(403);
  return { unverified, verified, linked, accounts, untrustedRedirect };
});
