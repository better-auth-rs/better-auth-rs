import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

compatScenario("magic link proves mailbox ownership, revokes unproven access, and rejects replay", async (ctx) => {
  const email = ctx.uniqueEmail("magic-owner");
  const previous = await ctx.actor("previous").client.signUp.email({ email, password: "password123", name: "Previous Name" });
  expect(previous.error).toBeNull();
  const sent = await ctx.rawRequest({ path: "/api/auth/sign-in/magic-link", method: "POST", json: { email, name: "Unused Name", metadata: { purpose: "proof" } } });
  expect(sent).toEqual({ status: 200, location: null, body: { status: true } });
  const message = await ctx.readVerificationEmail({ email }) as { token: string; url: string; metadata: unknown };
  expect(message.token).toMatch(/^[A-Za-z]{32}$/);
  expect(new URL(message.url).searchParams.get("callbackURL")).toBe("/");
  expect(message.metadata).toEqual({ purpose: "proof" });
  const unsafe = await ctx.rawRequest({ path: `/api/auth/magic-link/verify?token=${message.token}&callbackURL=${encodeURIComponent("https://attacker.invalid/")}`, redirect: "manual" });
  expect(unsafe.status).toBe(403);
  const verified = await ctx.rawRequest({ path: `/api/auth/magic-link/verify?token=${message.token}`, redirect: "manual" });
  expect(verified.status).toBe(200);
  const proof = verified.body as { user: { id: string; name: string; emailVerified: boolean }; session: { userId: string } };
  expect(proof.user.id).toBe(previous.data!.user.id);
  expect(proof.user.emailVerified).toBe(true);
  expect(proof.user.name).toBe("Previous Name");
  expect(proof.session.userId).toBe(proof.user.id);
  const oldSession = await ctx.actor("previous").client.getSession();
  expect(oldSession.data).toBeNull();
  const oldPassword = await ctx.actor("previous").client.signIn.email({ email, password: "password123" });
  expect(oldPassword.error?.status).toBe(401);
  const replay = await ctx.rawRequest({ path: `/api/auth/magic-link/verify?token=${message.token}`, redirect: "manual" });
  expect(replay.status).toBe(302);
  expect(new URL(replay.location!).searchParams.get("error")).toBe("INVALID_TOKEN");
  return { sent, unsafe, verified, oldSession: ctx.snapshot(oldSession), oldPassword: ctx.snapshot(oldPassword), replay };
});

compatScenario("magic link creates a verified user and selects the signup redirect", async (ctx) => {
  const email = ctx.uniqueEmail("magic-new");
  const sent = await ctx.rawRequest({ path: "/api/auth/sign-in/magic-link", method: "POST", json: { email, name: "New Owner", callbackURL: "/return", newUserCallbackURL: "/welcome", errorCallbackURL: "/failure" } });
  expect(sent.status).toBe(200);
  const message = await ctx.readVerificationEmail({ email }) as { token: string; url: string };
  const verified = await ctx.rawRequest({ path: message.url, redirect: "manual" });
  expect(verified.status).toBe(302);
  expect(new URL(verified.location!).pathname).toBe("/welcome");
  const session = await ctx.actor().client.getSession();
  expect(session.data!.user.email).toBe(email);
  expect(session.data!.user.emailVerified).toBe(true);
  expect(session.data!.user.name).toBe("New Owner");
  return { sent, verified, session: ctx.snapshot(session) };
});
