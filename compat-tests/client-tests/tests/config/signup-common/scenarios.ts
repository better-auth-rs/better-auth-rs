import { expect } from "bun:test";
import { compatScenario } from "../../../support/scenario";

export function signupScenarios(mode: "enumeration" | "verification" | "synthetic") {
  compatScenario("protected duplicate signup returns a fresh synthetic user without modifying the account", async ctx => {
    const email = ctx.uniqueEmail("signup-protected");
    const password = "Password123!";
    const original = await ctx.rawRequest({ path: "/api/auth/sign-up/email", method: "POST", json: { name: "Original Name", email, password } });
    expect(original.status).toBe(200);
    expect((original.body as any).token).toBeNull();
    const noSession = await ctx.actor().client.getSession();
    expect(noSession.data).toBeNull();
    const submitted = { name: "Submitted Name", email: email.toUpperCase(), password: "DifferentPassword123!", image: "https://example.com/synthetic.png", alias: "submitted" };
    const duplicate = await ctx.rawRequest({ path: "/api/auth/sign-up/email", method: "POST", json: submitted, headers: { "x-expected-user-name": "Original Name" } });
    expect(duplicate.status, JSON.stringify(duplicate.body)).toBe(200);
    const user = (duplicate.body as any).user;
    expect((duplicate.body as any).token).toBeNull();
    expect(user).toMatchObject({ email, emailVerified: false, name: mode === "synthetic" ? "synthetic:Submitted Name" : "Submitted Name", image: submitted.image, alias: mode === "synthetic" ? "custom:submitted:in" : "submitted:in", optionalAlias: null, role: null, banned: false });
    expect(user.id).not.toBe((original.body as any).user.id);
    expect(user).not.toHaveProperty("secretNote");
    expect(user).not.toHaveProperty("unknown");
    const rejected = await ctx.rawRequest({ path: "/api/auth/sign-up/email", method: "POST", json: submitted, headers: { "x-duplicate-error": "1" } });
    expect(rejected.status).toBe(200);
    expect((rejected.body as any).token).toBeNull();
    expect((rejected.body as any).user.id).not.toBe(user.id);
    const wrong = await ctx.actor("wrong").client.signIn.email({ email, password: submitted.password });
    expect(wrong.error?.status).toBe(401);
    const login = await ctx.actor("owner").client.signIn.email({ email, password });
    if (mode === "verification") {
      expect(login.error?.status).toBe(403);
      expect(login.error?.code).toBe("EMAIL_NOT_VERIFIED");
      const sent = await fetch(`${ctx.baseURL}/__test/verification-email?email=${encodeURIComponent(email)}`).then(response => response.json());
      expect(sent.token).toBeString();
      const verified = await ctx.rawRequest({ path: `/api/auth/verify-email?token=${encodeURIComponent(sent.token)}` });
      expect(verified.status).toBe(200);
      const afterVerification = await ctx.actor("verified").client.signIn.email({ email, password });
      expect(afterVerification.error).toBeNull();
      expect(afterVerification.data?.user.emailVerified).toBe(true);

    } else {
      expect(login.error).toBeNull();
      expect(login.data?.user.name).toBe("Original Name");
      expect(login.data?.user.id).toBe((original.body as any).user.id);
    }
    return { original, noSession: ctx.snapshot(noSession), duplicate, rejected, wrong: ctx.snapshot(wrong), login: ctx.snapshot(login) };
  });
}
